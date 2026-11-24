"""Explicit publication of public monitoring metadata for node_exporter."""
import os
from pathlib import Path
import secrets
import stat

from . import core, storage


class MetricsFileError(core.Error):
    pass


def _path(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.suffix != '.prom':
        raise ValueError
    for protected in (core.STATE, core.CONFIG.parent, core.LIVE.parent):
        if path.is_relative_to(protected.absolute()):
            raise ValueError
    return path


def _target(directory, path):
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
    finally:
        os.close(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1):
        raise ValueError
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def write(path, text):
    """Replace a selected .prom file; never create or repair output directories.

    Before replacement the previous file remains untouched. A failed directory
    fsync after replacement means the new file may be visible but not durable.
    Root and concurrent processes with the same effective UID remain trusted.
    """
    try:
        path = _path(path)
        if not isinstance(text, str) or not text.endswith('\n'):
            raise ValueError
        with storage._directory(path.parent, create=False, private=False) as directory:
            if stat.S_IMODE(os.fstat(directory).st_mode) & 0o022:
                raise ValueError
            previous = _target(directory, path)
            temporary = '.cgp-metrics-' + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                with storage._text_stream(fd, 'w') as stream:
                    stream.write(text)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o644)
                    os.fsync(stream.fileno())
                if _target(directory, path) != previous:
                    raise ValueError
                os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
    except Exception:
        raise MetricsFileError('Metrics file publication failed') from None
