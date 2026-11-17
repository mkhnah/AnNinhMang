"""Run backend tests on a checksum-verified Linux source copy (WSL/ext4)."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    source = Path(__file__).resolve().parents[1]
    destination = Path(tempfile.mkdtemp(prefix='docsign-regression-', dir='/tmp'))
    names = ['backend', 'tests', 'scripts', 'frontend/src']
    for name in names:
        shutil.copytree(source / name, destination / name, ignore=shutil.ignore_patterns('__pycache__', '.pytest_cache'))
    for name in ['alembic.ini', 'pytest.ini', 'frontend/package.json', 'frontend/package-lock.json']:
        if (source / name).exists():
            shutil.copy2(source / name, destination / name)
    files = [path for name in names for path in (destination / name).rglob('*') if path.is_file()]
    for path in files:
        original = source / path.relative_to(destination)
        if hashlib.sha256(original.read_bytes()).digest() != hashlib.sha256(path.read_bytes()).digest():
            raise RuntimeError(f'Source mismatch: {path.relative_to(destination)}')
    (destination / 'frontend/node_modules').symlink_to(source / 'frontend/node_modules', target_is_directory=True)
    (destination / 'data/db').mkdir(parents=True)
    env = {**os.environ, 'SECRET_KEY':'regression-secret-' * 4, 'JWT_SECRET_KEY':'regression-jwt-' * 4,
        'PKI_ENABLED':'false', 'TSA_ENABLED':'false', 'DEBUG':'false', 'PYTHONPATH':str(destination)}
    esbuild = source / 'data/tmp/phase7-esbuild/package/bin/esbuild'
    if esbuild.exists():
        env['ESBUILD_BINARY_PATH'] = str(esbuild)
    print(f'Verified {len(files)} source files; workspace {destination}', flush=True)
    result = subprocess.run([sys.executable, '-m', 'pytest', *(sys.argv[1:] or ['tests', '-q'])], cwd=destination, env=env)
    print(f'TEST_WORKSPACE {destination}', flush=True)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
