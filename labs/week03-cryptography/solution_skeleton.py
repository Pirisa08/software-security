"""
Week 3 — FIX the misuse here.
pip install argon2-cffi pycryptodome
"""

import os
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher, Type
from Crypto.Cipher import AES


# Use Argon2id for password hashing
ph = PasswordHasher(type=Type.ID)


def store_password(pw: str) -> str:
    # Argon2id automatically uses a random salt
    return ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False


def is_legacy_md5(hash_: str) -> bool:
    # MD5 hashes are 32 hexadecimal characters
    return (
        len(hash_) == 32
        and all(c in "0123456789abcdefABCDEF" for c in hash_)
    )


def verify_and_rehash(hash_: str, pw: str):
    # Legacy account still using MD5
    if is_legacy_md5(hash_):
        old_hash = hashlib.md5(pw.encode()).hexdigest()

        if hmac.compare_digest(old_hash, hash_):
            # Correct login -> upgrade password to Argon2id
            new_hash = store_password(pw)
            return True, new_hash

        return False, None

    # Account already using Argon2id
    try:
        if ph.verify(hash_, pw):
            if ph.check_needs_rehash(hash_):
                return True, store_password(pw)

            return True, None

    except Exception:
        pass

    return False, None


def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # AES-GCM with a fresh random 12-byte nonce
    nonce = os.urandom(12)

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return nonce, ciphertext, tag


def decrypt_gcm(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    key: bytes
) -> bytes:

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    # Fails if ciphertext or tag was modified
    return cipher.decrypt_and_verify(ciphertext, tag)


def reset_token() -> str:
    # CSPRNG for security-sensitive tokens
    return secrets.token_urlsafe(16)


if __name__ == "__main__":

    print("=== Task 6: Password migration ===")

    # Normal Argon2id password
    h = store_password("password123")

    print("argon2 ok:", verify_password(h, "password123"))
    print("argon2 hash:", h)

    # Simulate a legacy MD5 account
    legacy_hash = hashlib.md5(
        b"password123"
    ).hexdigest()

    ok, new_hash = verify_and_rehash(
        legacy_hash,
        "password123"
    )

    print("legacy MD5:", legacy_hash)
    print("legacy login:", ok)
    print("upgraded hash:", new_hash)
    print(
        "is argon2id:",
        new_hash is not None
        and new_hash.startswith("$argon2id$")
    )


    print("\n=== Task 7: AES-GCM ===")

    # Key MUST come from environment variable
    enc_key_hex = os.environ.get("ENC_KEY_HEX")

    if not enc_key_hex:
        raise RuntimeError(
            "ENC_KEY_HEX environment variable is required"
        )

    key = bytes.fromhex(enc_key_hex)

    if len(key) not in (16, 24, 32):
        raise ValueError(
            "ENC_KEY_HEX must contain a valid AES key "
            "(16, 24, or 32 bytes)"
        )

    message = b"secret message"

    # Encrypt
    nonce, ciphertext, tag = encrypt_gcm(
        message,
        key
    )

    print("nonce length:", len(nonce))
    print("nonce:", nonce.hex())
    print("ciphertext:", ciphertext.hex())
    print("tag:", tag.hex())

    # Normal decrypt
    decrypted = decrypt_gcm(
        nonce,
        ciphertext,
        tag,
        key
    )

    print("decrypted:", decrypted)
    print("round trip ok:", decrypted == message)


    # Tamper with one ciphertext byte
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    try:
        decrypt_gcm(
            nonce,
            bytes(tampered),
            tag,
            key
        )

        print("tampered decrypt: UNEXPECTED SUCCESS")

    except ValueError as e:
        print("tampered decrypt failed:", e)


    print("\n=== Secure reset token ===")
    print("token:", reset_token())