"""Hash exact binary content without buffering the whole document."""
import hashlib
from typing import BinaryIO


def sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        digest.update(chunk)
    return digest.hexdigest()
