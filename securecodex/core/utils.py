
import hashlib
import os

def calculate_file_hash(file_path: str) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return ""

def is_file_changed(file_path: str, old_hash: str) -> bool:
    """Check if a file has changed by comparing its current hash with a stored one."""
    current_hash = calculate_file_hash(file_path)
    return current_hash != old_hash
