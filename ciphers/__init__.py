"""Built-in reference cipher adapters (comparison baselines).

Each adapter subclasses :class:`analyzer.ingest.CipherAdapter`. Only ciphers that
pass their test-vector self-check are registered here; ``a51`` / ``grain128`` /
``zuc256`` are added once their implementations are verified.
"""

from .a51 import A51
from .chacha20 import ChaCha20
from .grain128 import Grain128
from .salsa20 import Salsa20
from .trivium import Trivium

BUILTIN = {
    "chacha20": ChaCha20,
    "trivium": Trivium,
    "salsa20": Salsa20,
    "a51": A51,
    "grain128": Grain128,
}

__all__ = ["BUILTIN", "ChaCha20", "Trivium", "Salsa20", "A51", "Grain128"]
