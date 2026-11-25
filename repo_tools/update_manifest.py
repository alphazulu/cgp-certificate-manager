"""Assemble an unsigned update manifest from locally reviewed release artifacts.

Provenance is an input, not an authentication mechanism. This helper verifies
the archive it describes and emits canonical bytes for a separate signer. It
never creates keys, signatures, trust files, tags, or release publications.
"""
import argparse
import os
from pathlib import Path
import stat
import sys

from cgp_cert_manager import storage, update_archive, update_metadata as metadata


def create(provenance_bytes, archive_bytes, *, channel, sequence, issued_at, expires_at):
    """Return canonical manifest bytes; do not import or execute candidate code."""
    provenance = metadata._json(provenance_bytes, metadata.MAX_MANIFEST, "invalid_provenance")
    if (not isinstance(provenance, dict)
            or set(provenance) != {"schema", "commit", "tree", "version", "release_tag", "prefix", "archive"}
            or type(provenance["schema"]) is not int or provenance["schema"] != 1):
        raise metadata.UpdateError("invalid_provenance")
    version = provenance["version"]
    metadata.version(version, allow_dev=False)
    if (provenance["prefix"] != metadata.PROJECT + "-v" + version
            or provenance["release_tag"] != "v" + version):
        raise metadata.UpdateError("invalid_provenance")
    manifest = {
        "schema": 1, "project": metadata.PROJECT, "channel": channel,
        "sequence": sequence, "version": version, "issued_at": issued_at,
        "expires_at": expires_at,
        "source": {"repository": metadata.REPOSITORY, "commit": provenance["commit"],
                   "tree": provenance["tree"], "tag": provenance["release_tag"]},
        "archive": provenance["archive"],
    }
    data = metadata.canonical(manifest)
    validated, _ = metadata._manifest(data)
    update_archive.inspect_archive(archive_bytes, validated)
    return data


def _witness(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(value, limit):
    path = Path(value).absolute()
    if ".." in path.parts or path == Path(path.anchor):
        raise metadata.UpdateError("invalid_input")
    with storage._directory(path.parent, private=False) as parent:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in (0, os.geteuid()) or before.st_mode & 0o7022
                    or before.st_size < 1 or before.st_size > limit):
                raise metadata.UpdateError("invalid_input")
            data = stream.read(limit + 1)
            if len(data) != before.st_size or _witness(before) != _witness(os.fstat(stream.fileno())):
                raise metadata.UpdateError("input_changed")
            return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Emit an unsigned canonical update manifest to stdout")
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--channel", choices=("stable", "candidate"), required=True)
    for name in ("sequence", "issued-at", "expires-at"):
        parser.add_argument("--" + name, type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        data = create(_read(arguments.provenance, metadata.MAX_MANIFEST),
                      _read(arguments.archive, metadata.MAX_ARCHIVE),
                      channel=arguments.channel, sequence=arguments.sequence,
                      issued_at=arguments.issued_at, expires_at=arguments.expires_at)
    except (metadata.UpdateError, storage.StorageError, OSError, ValueError):
        print("Cannot assemble update manifest: invalid or unreadable release artifacts", file=sys.stderr)
        return 2
    sys.stdout.write(data.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
