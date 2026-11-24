"""Read one local public certificate without invoking Certbot or a network API.

Only the standard same-lineage live/archive link and regular live cert.pem are
accepted. Trusted owners may still change their own files: this is a bounded,
read-only observation, not a sandbox against root or proof of a deployed leaf.
"""

import math
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess

from . import core, storage


MAX_CERTIFICATE_BYTES = 64 * 1024


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(before.st_mode) & 0o022 or before.st_nlink != 1
                or before.st_size > MAX_CERTIFICATE_BYTES):
            raise core.Error('Unsafe public certificate')
        chunks = []
        remaining = MAX_CERTIFICATE_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        pem = b''.join(chunks)
        if (len(pem) > MAX_CERTIFICATE_BYTES or len(pem) != before.st_size
                or _stamp(before) != _stamp(os.fstat(fd))):
            raise core.Error('Public certificate changed during observation')
        return pem
    finally:
        os.close(fd)


def _archive_name(target, lineage, live):
    relative = '../../archive/' + lineage + '/'
    absolute = str(live.parent / 'archive' / lineage) + '/'
    if target.startswith(relative):
        name = target[len(relative):]
    elif target.startswith(absolute):
        name = target[len(absolute):]
    else:
        raise core.Error('Unsupported public certificate link')
    if not re.fullmatch(r'cert[1-9][0-9]*\.pem', name):
        raise core.Error('Unsupported public certificate link')
    return name


def _leaf(lineage, live):
    # The shared directory walker pins each directory without following links.
    # Public certificates need trusted ancestry, not private 0700 directories.
    with storage._directory(live / lineage, private=False, missing_ok=True) as directory:
        if directory is None:
            return None
        try:
            before = os.stat('cert.pem', dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(before.st_mode):
            if before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1:
                raise core.Error('Unsafe public certificate link')
            name = _archive_name(os.readlink('cert.pem', dir_fd=directory), lineage, live)
            with storage._directory(live.parent / 'archive' / lineage, private=False) as archive:
                pem = _read(archive, name)
        else:
            pem = _read(directory, 'cert.pem')
        after = os.stat('cert.pem', dir_fd=directory, follow_symlinks=False)
        if _stamp(before) != _stamp(after):
            raise core.Error('Public certificate link changed during observation')
        return pem


def inspect(lineage, live=None):
    """Return exactly ok+not_after, missing, or error using local public data."""
    try:
        if not isinstance(lineage, str) or len(lineage) > 255:
            raise core.Error('Invalid certificate lineage')
        core.identifier(lineage)
        live = Path(core.LIVE if live is None else live)
        if not live.is_absolute():
            raise core.Error('Invalid certificate directory')
        pem = _leaf(lineage, live)
        if pem is None:
            return {'status': 'missing'}
        if not re.fullmatch(rb'\s*-----BEGIN CERTIFICATE-----\s+'
                            rb'[A-Za-z0-9+/=\r\n\t ]+-----END CERTIFICATE-----\s*', pem):
            raise core.Error('Invalid public certificate')
        output = core.run('openssl', 'x509', '-noout', '-enddate', data=pem, timeout=10).decode('ascii').strip()
        prefix, _, date = output.partition('=')
        if prefix != 'notAfter':
            raise core.Error('Invalid certificate expiry')
        expiry = ssl.cert_time_to_seconds(date)
        if type(expiry) not in (int, float) or not math.isfinite(expiry):
            raise core.Error('Invalid certificate expiry')
        return {'status': 'ok', 'not_after': expiry}
    except (core.Error, OSError, ValueError, TypeError, OverflowError, subprocess.SubprocessError):
        return {'status': 'error'}
