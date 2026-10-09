import os
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet


@lru_cache
def encryption_key():
    value = os.getenv("CHECKMAYO_ENCRYPTION_KEY")
    if value:
        return value.encode()
    root = Path(os.getenv("CHECKMAYO_STATE_DIR", "state"))
    root.mkdir(parents=True, exist_ok=True)
    key_file = root / "encryption.key"
    if not key_file.exists():
        try:
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(Fernet.generate_key())
        except FileExistsError:
            pass
    return key_file.read_bytes()


def encrypt(value):
    return Fernet(encryption_key()).encrypt(value.encode()).decode()


def decrypt(value):
    return Fernet(encryption_key()).decrypt(value.encode()).decode()
