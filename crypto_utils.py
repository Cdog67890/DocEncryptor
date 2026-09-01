from __future__ import annotations

import base64
import os
import struct
import tempfile
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LEGACY_MAGIC = b"SFE1"
MAGIC = b"SFE2"
FORMAT_VERSION = 2
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
ARGON2_ITERATIONS = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_LANES = 4
HEADER = struct.Struct(">4sBBBBIII16s12sQ")
# magic, version, kdf_id, cipher_id, flags, iterations, memory_kib, lanes, salt, nonce, plaintext_size
KDF_ARGON2ID = 1
CIPHER_AES256_GCM = 1
PBKDF2_ITERATIONS = 600_000
ProgressCallback = Callable[[int, int], None]


class SecureFileError(Exception):
    pass


class UnsupportedFormatError(SecureFileError):
    pass


class AuthenticationError(SecureFileError):
    pass


def _derive_v2_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(salt) != SALT_SIZE:
        raise ValueError("invalid salt length")
    return Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    ).derive(password.encode("utf-8"))


def _derive_legacy_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _validate_paths(input_path: Path, output_path: Path, overwrite: bool) -> None:
    if not input_path.exists() or not input_path.is_file():
        raise FileNotFoundError(f"File not found: {input_path}")
    if input_path.resolve() == output_path.resolve():
        raise SecureFileError("Input and output paths must be different.")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)


def _temp_path_for(output_path: Path) -> tuple[int, str]:
    return tempfile.mkstemp(prefix=f".{output_path.name}.", suffix=".tmp", dir=str(output_path.parent))


def encrypt_file(
    input_filename: str | os.PathLike[str],
    output_filename: str | os.PathLike[str],
    password: str,
    *,
    overwrite: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> Path:
    input_path, output_path = Path(input_filename), Path(output_filename)
    _validate_paths(input_path, output_path, overwrite)
    total = input_path.stat().st_size
    salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
    key = _derive_v2_key(password, salt)
    header = HEADER.pack(
        MAGIC, FORMAT_VERSION, KDF_ARGON2ID, CIPHER_AES256_GCM, 0,
        ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_LANES,
        salt, nonce, total,
    )
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    fd, temp_name = _temp_path_for(output_path)
    processed = 0
    try:
        with os.fdopen(fd, "wb") as dst, input_path.open("rb") as src:
            dst.write(header)
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(encryptor.update(chunk))
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, total)
            dst.write(encryptor.finalize())
            dst.write(encryptor.tag)
            dst.flush(); os.fsync(dst.fileno())
        if output_path.exists() and not overwrite:
            raise FileExistsError(f"Output file already exists: {output_path}")
        os.replace(temp_name, output_path)
        if progress_callback:
            progress_callback(total, total)
        return output_path
    except Exception:
        try: os.unlink(temp_name)
        except FileNotFoundError: pass
        raise


def _decrypt_v2(input_path: Path, output_path: Path, password: str, overwrite: bool, progress_callback: ProgressCallback | None) -> Path:
    actual_size = input_path.stat().st_size
    if actual_size < HEADER.size + TAG_SIZE:
        raise SecureFileError("Encrypted file is truncated or corrupted.")
    with input_path.open("rb") as src:
        header = src.read(HEADER.size)
        magic, version, kdf_id, cipher_id, flags, iters, mem, lanes, salt, nonce, plaintext_size = HEADER.unpack(header)
        if magic != MAGIC or version != FORMAT_VERSION:
            raise UnsupportedFormatError("Unsupported Secure File Encryptor format.")
        if (kdf_id, cipher_id, flags) != (KDF_ARGON2ID, CIPHER_AES256_GCM, 0):
            raise UnsupportedFormatError("Unsupported encryption settings in this file.")
        if (iters, mem, lanes) != (ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_LANES):
            raise UnsupportedFormatError("Unsupported key-derivation settings in this file.")
        expected = HEADER.size + plaintext_size + TAG_SIZE
        if actual_size != expected:
            raise SecureFileError("Encrypted file is truncated, extended, or corrupted.")
        src.seek(actual_size - TAG_SIZE)
        tag = src.read(TAG_SIZE)
        src.seek(HEADER.size)
        key = _derive_v2_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        fd, temp_name = _temp_path_for(output_path)
        remaining = plaintext_size
        processed = 0
        try:
            with os.fdopen(fd, "wb") as dst:
                while remaining:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise SecureFileError("Encrypted file ended unexpectedly.")
                    dst.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                    processed += len(chunk)
                    if progress_callback:
                        progress_callback(processed, plaintext_size)
                dst.write(decryptor.finalize())
                dst.flush(); os.fsync(dst.fileno())
            if output_path.exists() and not overwrite:
                raise FileExistsError(f"Output file already exists: {output_path}")
            os.replace(temp_name, output_path)
            if progress_callback:
                progress_callback(plaintext_size, plaintext_size)
            return output_path
        except InvalidTag as exc:
            try: os.unlink(temp_name)
            except FileNotFoundError: pass
            raise AuthenticationError("Incorrect password, or the encrypted file was modified/corrupted.") from exc
        except Exception:
            try: os.unlink(temp_name)
            except FileNotFoundError: pass
            raise


def _decrypt_v1_or_legacy(input_path: Path, output_path: Path, password: str, overwrite: bool) -> Path:
    payload = input_path.read_bytes()
    if payload.startswith(LEGACY_MAGIC):
        if len(payload) <= 5 + SALT_SIZE:
            raise SecureFileError("Encrypted file is truncated or corrupted.")
        version = payload[4]
        if version != 1:
            raise UnsupportedFormatError(f"Unsupported SFE1 format version: {version}")
        salt = payload[5:5 + SALT_SIZE]
        token = payload[5 + SALT_SIZE:]
    else:
        if len(payload) <= SALT_SIZE:
            raise SecureFileError("Encrypted file is too short or corrupted.")
        salt, token = payload[:SALT_SIZE], payload[SALT_SIZE:]
    try:
        plaintext = Fernet(_derive_legacy_key(password, salt)).decrypt(token)
    except InvalidToken as exc:
        raise AuthenticationError("Incorrect password, or the encrypted file was modified/corrupted.") from exc
    fd, temp_name = _temp_path_for(output_path)
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(plaintext); dst.flush(); os.fsync(dst.fileno())
        if output_path.exists() and not overwrite:
            raise FileExistsError(f"Output file already exists: {output_path}")
        os.replace(temp_name, output_path)
        return output_path
    except Exception:
        try: os.unlink(temp_name)
        except FileNotFoundError: pass
        raise


def decrypt_file(
    encrypted_filename: str | os.PathLike[str],
    output_filename: str | os.PathLike[str],
    password: str,
    *,
    overwrite: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> Path:
    input_path, output_path = Path(encrypted_filename), Path(output_filename)
    _validate_paths(input_path, output_path, overwrite)
    with input_path.open("rb") as src:
        prefix = src.read(4)
    if prefix == MAGIC:
        return _decrypt_v2(input_path, output_path, password, overwrite, progress_callback)
    return _decrypt_v1_or_legacy(input_path, output_path, password, overwrite)
