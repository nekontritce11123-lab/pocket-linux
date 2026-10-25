"""Package only the portable payload, excluding profiles, credentials and live state."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time
import zipfile

FILES = ('Launcher.exe', 'release-info.json', 'linux.qcow2', 'start.py', 'README.txt', 'COMPONENTS.json',
         'runtime/components-recovery.zip', 'runtime/components-manifest.json', 'scripts/Prepare-Dependencies.ps1',
         'scripts/portable_app.py', 'scripts/runtime_supervisor.py',
         'scripts/profile_store.py', 'scripts/connection_profile.py', 'scripts/host_folders.py',
         'scripts/clipboard_bridge.py', 'scripts/linux_window.py', 'scripts/guest_status.py')
DIRECTORIES = ('third-party',)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def payload(root):
    root = root.resolve(strict=True)
    paths = [root / name for name in FILES]
    for name in DIRECTORIES:
        folder = root / name
        for component in (folder, *folder.parents):
            if component == root:
                break
            if component.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError('Reparse points cannot be packaged')
        if not folder.is_dir():
            raise ValueError('Missing portable directory: ' + name)
        for current, directories, files in os.walk(folder, followlinks=False):
            for name in directories + files:
                candidate = Path(current) / name
                if candidate.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError('Reparse points cannot be packaged')
            paths.extend(Path(current) / name for name in files)
    for path in paths:
        if (not path.is_file() or not path.resolve().is_relative_to(root)
                or path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError('Unsafe or missing package file: ' + path.name)
    return sorted(paths)


def package(root, archive, extraction):
    root = root.resolve(strict=True)
    if archive.exists() or extraction.exists():
        raise ValueError('Archive and verification extraction must be new paths')
    files = payload(root)
    manifest = {p.relative_to(root).as_posix(): {'bytes': p.stat().st_size, 'sha256': digest(p)} for p in files}
    started = time.monotonic()
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as output:
        for path in files:
            output.write(path, 'Pocket-Linux/' + path.relative_to(root).as_posix())
        output.writestr('Pocket-Linux/SHA256SUMS.json', json.dumps(manifest, indent=2))
    extraction.mkdir()
    components = {}
    with zipfile.ZipFile(archive) as packed:
        for entry in packed.infolist():
            name = PurePosixPath(entry.filename)
            if name.is_absolute() or '..' in name.parts or name.parts[0] != 'Pocket-Linux':
                raise ValueError('Unsafe archive member')
            relative = '/'.join(name.parts[1:])
            target = extraction.joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            checksum = hashlib.sha256()
            with packed.open(entry) as source, target.open('xb') as out:
                while data := source.read(1024 * 1024):
                    checksum.update(data)
                    out.write(data)
            # Reading to EOF also validates ZIP CRC; compare every extracted byte to the original manifest.
            if relative in manifest and checksum.hexdigest() != manifest[relative]['sha256']:
                raise ValueError('Extracted checksum mismatch: ' + relative)
            category = 'linux.qcow2' if relative == 'linux.qcow2' else '/'.join(name.parts[1:3]) if name.parts[1] == 'runtime' else 'application'
            components[category] = components.get(category, 0) + entry.compress_size
    result = {'archive': str(archive), 'archive_bytes': archive.stat().st_size,
              'sha256': digest(archive), 'payload_bytes': sum(v['bytes'] for v in manifest.values()),
              'files': len(manifest), 'compressed_components': components,
              'crc_and_all_extracted_sha256': True, 'verification_extraction': str(extraction / 'Pocket-Linux'),
              'seconds': round(time.monotonic() - started, 3)}
    archive.with_suffix(archive.suffix + '.sha256').write_text(result['sha256'] + '  ' + archive.name + '\n', encoding='utf-8')
    archive.with_suffix('.size.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--extraction', type=Path, required=True)
    args = parser.parse_args()
    package(args.root, args.archive, args.extraction)
