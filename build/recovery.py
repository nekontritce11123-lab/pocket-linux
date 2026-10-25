"""Build one offline runtime bundle from a private stage; never read profiles or Linux disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
import zipfile

ROOTS = ('runtime/python-3.12.14', 'runtime/qemu-11.1.0', 'runtime/host-files')
ESSENTIAL = ('PocketNet.exe', 'runtime/python-3.12.14/python.exe',
             'runtime/qemu-11.1.0/qemu-system-x86_64.exe', 'runtime/qemu-11.1.0/qemu-img.exe',
             'runtime/host-files/HostFiles.exe')
MAX_FILES = 16384
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def valid_name(name):
    if not isinstance(name, str) or not 1 <= len(name) <= 1024:
        return False
    if name != 'PocketNet.exe' and not re.fullmatch(r'runtime/(python-3\.12\.14|qemu-11\.1\.0|host-files)/[^/]+(?:/[^/]+)*', name):
        return False
    return not any(part in ('.', '..') or part.endswith(('.', ' '))
                   or re.search(r'[\\:<>"|?*\x00-\x1f]', part)
                   or re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part)
                   for part in name.split('/'))


def plain(path):
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse paths cannot be bundled')
        if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ValueError('Only regular unlinked files can be bundled')


def inventory(root):
    if any(not (root / name).is_file() for name in ESSENTIAL):
        raise ValueError('A required runtime executable is missing')
    files = [root / 'PocketNet.exe']
    for name in ROOTS:
        directory = root / name
        plain(directory)
        if not directory.is_dir():
            raise ValueError('A required runtime directory is missing')
        for current, directories, names in os.walk(directory, followlinks=False):
            for child in directories + names:
                plain(Path(current) / child)
            files.extend(Path(current) / name for name in names)
    seen, total = set(), 0
    for path in files:
        plain(path)
        if not path.is_file():
            raise ValueError('A required runtime file is missing')
        name = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if not valid_name(name) or name.casefold() in seen or not 0 <= size <= MAX_FILE_BYTES:
            raise ValueError('Invalid or duplicate runtime member')
        seen.add(name.casefold())
        total += size
        if len(seen) > MAX_FILES or total > MAX_TOTAL_BYTES:
            raise ValueError('Runtime bundle exceeds its bounds')
    return sorted(files)


def build_recovery(stage_root):
    root = Path(stage_root).absolute()
    plain(root)
    if not root.is_dir():
        raise ValueError('Stage root must exist')
    files = inventory(root)
    archive = root / 'runtime/components-recovery.zip'
    manifest = root / 'runtime/components-manifest.json'
    for path in (archive, manifest):
        plain(path)
        if path.exists():
            raise ValueError('Recovery outputs already exist; use a fresh private stage')
    suffix = uuid.uuid4().hex
    temporary_zip = archive.with_name('.components-' + suffix + '.zip.tmp')
    temporary_manifest = manifest.with_name('.components-' + suffix + '.json.tmp')
    records = []
    payload_bytes = 0
    try:
        with zipfile.ZipFile(temporary_zip, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as packed:
            for path in files:
                plain(path)
                name = path.relative_to(root).as_posix()
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                # The embedded Python 3.12 exposes per-entry compression level only through this field.
                info._compresslevel = 9
                checksum, count = hashlib.sha256(), 0
                with path.open('rb') as source, packed.open(info, 'w') as destination:
                    before = os.fstat(source.fileno())
                    while chunk := source.read(1024 * 1024):
                        count += len(chunk)
                        if count > before.st_size or count > MAX_FILE_BYTES:
                            raise ValueError('Source component changed while bundling')
                        checksum.update(chunk)
                        destination.write(chunk)
                    after = os.fstat(source.fileno())
                if (count != before.st_size or (before.st_ino, before.st_size, before.st_mtime_ns)
                        != (after.st_ino, after.st_size, after.st_mtime_ns)):
                    raise ValueError('Source component changed while bundling')
                plain(path)
                records.append({'path': name, 'bytes': count, 'sha256': checksum.hexdigest()})
                payload_bytes += count
                if payload_bytes > MAX_TOTAL_BYTES:
                    raise ValueError('Runtime bundle exceeds its bounds')
        with zipfile.ZipFile(temporary_zip) as packed:
            if len(packed.infolist()) != len(records):
                raise ValueError('Incomplete recovery archive')
            for record in records:
                with packed.open(record['path']) as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != record['sha256']:
                        raise ValueError('Recovery archive verification failed')
        with temporary_manifest.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump({'schema': 1, 'files': records}, stream, ensure_ascii=True, indent=2)
            stream.write('\n')
        for path in (archive, manifest):
            if path.exists():
                raise ValueError('Recovery output appeared while building')
        temporary_zip.rename(archive)
        temporary_manifest.rename(manifest)
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        return {'schema': 1, 'archive': str(archive), 'manifest': str(manifest),
                'files': len(records), 'payload_bytes': payload_bytes,
                'archive_bytes': archive.stat().st_size, 'archive_sha256': digest}
    finally:
        temporary_zip.unlink(missing_ok=True)
        temporary_manifest.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_recovery(args.root), ensure_ascii=True), flush=True)
