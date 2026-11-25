"""Standalone, read-only pending-update guard; no application imports.

The trusted installer also copies this module as cgp_update_gate.py outside the
replaceable application. Any pending entry blocks, regardless of its contents.
This protects supported operations, not arbitrary concurrent root/same-UID code.
"""
import os
from pathlib import Path
import stat


STATE_DIR = Path('/var/lib/cgp-update')
CODES = frozenset({'update_pending', 'update_gate_unsafe'})


class PendingUpdateError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _directory(info, private):
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        raise PendingUpdateError('update_gate_unsafe')
    if private:
        safe = info.st_uid == os.geteuid() and not mode & 0o7077
    else:
        safe = info.st_uid in (0, os.geteuid()) and (not mode & 0o022 or bool(mode & stat.S_ISVTX))
    if not safe:
        raise PendingUpdateError('update_gate_unsafe')


def require_idle(state_dir=None):
    """Refuse any pending marker or unsafe path, without creating files/locks."""
    try:
        path = Path(STATE_DIR if state_dir is None else state_dir)
        if not path.is_absolute() or path.anchor != '/' or '..' in path.parts or '\0' in str(path):
            raise PendingUpdateError('update_gate_unsafe')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open('/', flags)
        try:
            _directory(os.fstat(descriptor), not path.parts[1:])
            for index, part in enumerate(path.parts[1:]):
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    return
                try:
                    _directory(os.fstat(child), index == len(path.parts) - 2)
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            try:
                os.stat('pending.json', dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise PendingUpdateError('update_pending')
        finally:
            os.close(descriptor)
    except (OSError, TypeError, ValueError):
        raise PendingUpdateError('update_gate_unsafe') from None
