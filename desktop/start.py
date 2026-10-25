"""Portable technical entry point for the prepared Pocket Linux folder."""
import argparse
from contextlib import contextmanager
import ctypes
import json
import msvcrt
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading


def qemu_path(path):
    # This QEMU build uses ANSI file APIs; reuse the Windows edition's short-path workaround.
    path = Path(path)
    existing = path if path.exists() else path.parent
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(existing), buf, len(buf)):
        raise OSError('Не удалось подготовить путь для QEMU.')
    value = buf.value if path.exists() else str(Path(buf.value) / path.name)
    if not value.isascii():
        raise ValueError('На этом диске недоступны короткие имена. Перенеси папку в путь без кириллицы.')
    return value.replace('\\', '/')


def stream_port(address):
    match = re.fullmatch(r'127\.0\.0\.1:([1-9][0-9]{0,4})', address) if isinstance(address, str) else None
    if not match or int(match[1]) > 65535:
        raise ValueError('Сетевой процесс сообщил недопустимый локальный адрес.')
    return match[1]


def ready_address(line):
    if not isinstance(line, str) or len(line) > 8192:
        raise ValueError('Не получено подтверждение сетевого процесса.')
    try:
        ready = json.loads(line)
    except (ValueError, TypeError):
        raise ValueError('Не получено подтверждение сетевого процесса.') from None
    if (not isinstance(ready, dict) or ready.get('event') != 'READY'
            or ready.get('direct_fallback') is not False):
        raise ValueError('Сетевой процесс не подтвердил запрет прямого подключения.')
    address = ready.get('listen')
    stream_port(address)
    return address


def build_qemu(root, accel='tcg', address=None, path_fn=qemu_path,
               memory_mib=2048, vcpus=2, fullscreen=False, width=1280, height=800):
    root = Path(root)
    if accel not in ('tcg', 'whpx'):
        raise ValueError('Неизвестный режим ускорения.')
    for value, low, high in ((memory_mib, 1024, 32768), (vcpus, 1, 32),
                             (width, 640, 3840), (height, 480, 2160)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError('Недопустимые параметры виртуальной машины.')
    if type(fullscreen) is not bool:
        raise ValueError('Недопустимый режим окна.')
    qemu = root / 'runtime/qemu-11.1.0'
    block = {'driver': 'qcow2', 'file': {'driver': 'file', 'filename': path_fn(root / 'linux.qcow2')},
             'node-name': 'pldisk'}
    argv = [str(qemu / 'qemu-system-x86_64.exe'), '-name', 'Pocket Linux',
            '-machine', 'q35,smm=off', '-accel', 'tcg,thread=multi' if accel == 'tcg' else 'whpx',
            '-m', str(memory_mib), '-smp', str(vcpus), '-nodefaults', '-display', 'sdl,gl=off,window-close=off',
            '-device', 'VGA,vgamem_mb=64,xres=' + str(width) + ',yres=' + str(height),
            '-device', 'qemu-xhci,id=usb', '-device', 'usb-tablet,bus=usb.0',
            '-monitor', 'none', '-serial', 'none', '-L', path_fn(qemu / 'share'),
            '-blockdev', json.dumps(block, separators=(',', ':')),
            '-device', 'virtio-blk-pci,drive=pldisk,bootindex=1']
    # Bun (Claude Code) requires SSE4.2; the default qemu64 model hides it.
    argv.extend(['-cpu', 'max' if accel == 'tcg' else
                 'qemu64,ssse3=on,sse4.1=on,sse4.2=on,popcnt=on'])
    if fullscreen:
        argv.append('-full-screen')
    if address is None:
        argv.extend(['-nic', 'none'])
    else:
        net = {'type': 'stream', 'id': 'plnet', 'server': False,
               'addr': {'type': 'inet', 'host': '127.0.0.1', 'port': stream_port(address)}}
        argv.extend(['-netdev', json.dumps(net, separators=(',', ':')),
                     '-device', 'virtio-net-pci,netdev=plnet,mac=52:54:00:50:4c:01'])
    return argv


def stop_owned(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start_network(root):
    config = root / 'proxy.json'
    if not config.is_file():
        print('Интернет отключён: proxy.json не настроен. Linux запустится без сети.')
        return None, None
    process = subprocess.Popen([str(root / 'PocketNet.exe'), '--config', str(config)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
    result = queue.Queue(maxsize=1)

    def read_ready():
        try:
            result.put(process.stdout.readline(8193))
        except (OSError, UnicodeError):
            result.put('')

    threading.Thread(target=read_ready, daemon=True).start()
    try:
        try:
            address = ready_address(result.get(timeout=10))
        except queue.Empty:
            raise RuntimeError('Сетевой процесс не ответил. Linux не запущен; прямой выход запрещён.') from None
        if process.poll() is not None:
            raise RuntimeError('Сетевой процесс завершился. Проверь proxy.json; прямой выход запрещён.')
        return process, address
    except BaseException:
        stop_owned(process)
        if process.stdout:
            process.stdout.close()
        raise


@contextmanager
def disk_lock(path):
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'\0')
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError('Эта копия Linux уже запущена. Сначала выключи её.') from None
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def run(root, accel='tcg'):
    root = Path(root)
    for relative in ('linux.qcow2', 'runtime/qemu-11.1.0/qemu-system-x86_64.exe'):
        if not (root / relative).is_file():
            raise FileNotFoundError('В комплекте отсутствует ' + relative)
    state = root / 'state'
    state.mkdir(exist_ok=True)
    with disk_lock(state / 'linux.lock'):
        network, vm = None, None
        try:
            network, address = start_network(root)
            argv = build_qemu(root, accel, address)
            with (state / 'qemu-stderr.log').open('w', encoding='utf-8') as stderr:
                vm = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=stderr)
                print('Linux запускается. Для сохранения данных выключай его через меню рабочего стола.')
                while True:
                    try:
                        code = vm.wait()
                        break
                    except KeyboardInterrupt:
                        print('Выключи Linux через меню рабочего стола; ожидаю завершения.')
                if code:
                    raise RuntimeError('QEMU завершился с ошибкой. Подробности: state/qemu-stderr.log')
            return 0
        finally:
            stop_owned(vm)
            stop_owned(network)
            if network is not None and network.stdout:
                network.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accel', choices=('tcg', 'whpx'), default='tcg')
    options = parser.parse_args()
    try:
        return run(Path(__file__).resolve().parent, options.accel)
    except (OSError, ValueError, RuntimeError) as error:
        print('Не удалось запустить Linux: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
