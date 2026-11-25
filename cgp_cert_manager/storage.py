"""Private manager storage with descriptor-based path and ownership checks.

The installed manager runs as root. Tests and isolated development use the
effective UID instead. Other users must not control an ancestor or access a
private file; concurrent changes by the same trusted UID are not a sandbox.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat

from .core import Error


class StorageError(Error):
    pass


def _path(path):
    path = Path(path)
    if ".." in path.parts:
        raise StorageError("Parent traversal is not allowed in private storage paths")
    return path.absolute()


def _check_directory(info, path, private):
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        raise StorageError("Not a directory: " + str(path))
    if private:
        if info.st_uid != os.geteuid() or mode & 0o7077:
            raise StorageError("Unsafe private directory owner or permissions: " + str(path))
    elif info.st_uid not in (0, os.geteuid()) or (mode & 0o022 and not mode & stat.S_ISVTX):
        # Trusted sticky directories such as /tmp protect an owned child from
        # replacement by a different UID. Every child is independently checked.
        raise StorageError("Unsafe ancestor directory: " + str(path))


@contextmanager
def _directory(path, create=False, missing_ok=False, private=True):
    """Walk without following symlinks and keep the final directory open."""
    path = _path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        _check_directory(os.fstat(fd), Path(path.anchor), private and not path.parts[1:])
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    if missing_ok:
                        yield None
                        return
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass  # Another creator still has to pass the same checks.
                child = os.open(part, flags, dir_fd=fd)
            except OSError:
                raise StorageError("Unsafe or inaccessible directory: " + str(current)) from None
            try:
                _check_directory(os.fstat(child), current, private and current == path)
                if create:
                    # Retry a parent sync even when mkdir succeeded during a
                    # previous attempt whose fsync failed before completion.
                    os.fsync(fd)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def ensure_private_directory(path):
    with _directory(path, create=True):
        pass


def check_private_directory(path, missing_ok=False):
    with _directory(path, missing_ok=missing_ok) as fd:
        return fd is not None


def _check_file(info, path):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & ~0o600 or info.st_nlink != 1):
        raise StorageError("Unsafe private file type, owner, permissions or links: " + str(path))


def _file_fd(directory, name, path, flags, create=False):
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory)
    except FileNotFoundError:
        raise
    except OSError:
        raise StorageError("Unsafe or inaccessible private file: " + str(path)) from None
    try:
        _check_file(os.fstat(fd), path)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextmanager
def _text_stream(fd, mode):
    try:
        stream = os.fdopen(fd, mode, encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream


@contextmanager
def open_private(path, mode="r", create=False):
    """Validate the opened inode before reading, appending or truncating."""
    modes = {"r": os.O_RDONLY, "a": os.O_WRONLY | os.O_APPEND, "w": os.O_WRONLY}
    if mode not in modes:
        raise ValueError("Unsupported private file mode")
    path = _path(path)
    with _directory(path.parent, create=create, private=False) as directory:
        fd = _file_fd(directory, path.name, path, modes[mode], create)
        with _text_stream(fd, mode) as stream:
            if mode == "w":
                os.ftruncate(stream.fileno(), 0)
            yield stream


def check_private_file(path, missing_ok=False):
    try:
        with open_private(path):
            return True
    except FileNotFoundError:
        if not missing_ok:
            raise
        return False


def read_text(path):
    with open_private(path) as stream:
        return stream.read()


def _existing_file(directory, path):
    try:
        fd = _file_fd(directory, path.name, path, os.O_RDONLY)
    except FileNotFoundError:
        return
    os.close(fd)


def _atomic(path, write):
    path = _path(path)
    with _directory(path.parent, create=True, private=False) as directory:
        _existing_file(directory, path)
        name = ".cgp-" + secrets.token_hex(12)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with _text_stream(fd, "w") as stream:
                write(stream)
                stream.flush()
                os.fsync(stream.fileno())
            # Reject a newly introduced unsafe target instead of replacing it.
            _existing_file(directory, path)
            os.replace(name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass


def atomic_text(path, text):
    _atomic(path, lambda stream: stream.write(text))


def atomic_json(path, data):
    def write(stream):
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    _atomic(path, write)


def private_files(directory, suffix=".json", missing_ok=True):
    """Validate every selected file before returning a sorted list of paths."""
    directory = _path(directory)
    with _directory(directory, missing_ok=missing_ok) as fd:
        if fd is None:
            return []
        names = sorted(name for name in os.listdir(fd) if name.endswith(suffix))
        for name in names:
            opened = _file_fd(fd, name, directory / name, os.O_RDONLY)
            os.close(opened)
        return [directory / name for name in names]


def validate_tree(path, missing_ok=True):
    """Check private state recursively without reading file contents."""
    path = _path(path)
    with _directory(path, missing_ok=missing_ok) as directory:
        if directory is None:
            return
        for name in os.listdir(directory):
            child = path / name
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                validate_tree(child, missing_ok=False)
            else:
                opened = _file_fd(directory, name, child, os.O_RDONLY)
                os.close(opened)


@contextmanager
def operation_lock(state):
    ensure_private_directory(state)
    with open_private(Path(state) / "run.lock", "a", create=True) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield lock
