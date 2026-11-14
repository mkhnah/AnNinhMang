"""Descriptor-relative storage; never follow symlinks or replace existing files."""
import os
import re
import stat
import uuid
from pathlib import Path
from typing import BinaryIO

REPOSITORY = Path(__file__).resolve().parents[3]
KEY = re.compile(r"([0-9a-f-]{36})/(v[1-9][0-9]*_[0-9a-f-]{36}\.pdf)\Z")


class LocalStorageService:
    def __init__(self, root: str | Path):
        path = Path(os.path.abspath(root))
        if not path.is_relative_to(REPOSITORY):
            raise ValueError("Storage must be inside repository")
        fd = os.open(REPOSITORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.relative_to(REPOSITORY).parts:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        except OSError as error:
            raise ValueError('Unsafe or inaccessible storage root') from error
        finally:
            os.close(fd)
        self.root = path

    def _directory(self, key: str, create=False):
        match = KEY.fullmatch(key)
        if not match:
            raise ValueError("Invalid storage key")
        document, name = match.groups()
        uuid.UUID(document)
        uuid.UUID(name.split('_', 1)[1][:-4])
        # Walk from the repository fd so ancestor replacement cannot escape the root.
        fd = os.open(REPOSITORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in (*self.root.relative_to(REPOSITORY).parts, document):
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd, name
        except BaseException:
            os.close(fd)
            raise

    def save_file(self, key: str, stream: BinaryIO) -> None:
        directory, name = self._directory(key, create=True)
        temporary = f'.upload-{uuid.uuid4()}.tmp'
        published = False
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as output:
                while chunk := stream.read(65536):
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            # link is atomic and fails if destination exists, unlike os.replace/rename.
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            published = True
            os.fsync(directory)
        except BaseException:
            if published:
                os.unlink(name, dir_fd=directory)
            raise
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory)

    def get_file(self, key: str) -> BinaryIO:
        directory, name = self._directory(key)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise ValueError('Storage object is not a regular file')
            return os.fdopen(fd, 'rb')
        finally:
            os.close(directory)

    def exists(self, key: str) -> bool:
        try:
            with self.get_file(key):
                return True
        except FileNotFoundError:
            return False

    def delete_file(self, key: str) -> None:
        directory, name = self._directory(key)
        try:
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
