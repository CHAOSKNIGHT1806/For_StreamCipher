"""Built-in reference cipher adapters (comparison baselines).

Each adapter subclasses :class:`analyzer.ingest.CipherAdapter`. Register new
built-ins by adding an entry to ``BUILTIN``.
"""

from .chacha20 import ChaCha20

BUILTIN = {
    "chacha20": ChaCha20,
}

__all__ = ["BUILTIN", "ChaCha20"]
