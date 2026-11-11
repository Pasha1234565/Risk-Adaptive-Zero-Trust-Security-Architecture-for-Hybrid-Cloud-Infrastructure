"""Create local key files safely when several processes start at once.

Two workers that both find a key file missing must not each write a different
key (one of them would then sign or encrypt with a key the other cannot read).
The file is written completely to a private temporary name and then published
with a hard link, which fails if the target already exists. Every process ends
up reading the same bytes, and nobody ever reads a half-written file.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def _restrict_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        # Windows ignores POSIX modes; the data directory's ACL applies there.
        pass


def create_once(path: Path, data: bytes) -> bytes:
    """Write ``data`` to ``path`` unless it already exists; return the file's
    contents, which are the bytes of whichever process published first."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    try:
        with open(temp, "xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_permissions(temp)
        try:
            os.link(temp, path)
        except FileExistsError:
            pass
        except OSError:
            # File systems without hard links: fall back to an exclusive create.
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    return path.read_bytes()
