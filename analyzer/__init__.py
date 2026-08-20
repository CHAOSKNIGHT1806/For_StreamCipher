"""Stream Cipher Security Analyzer.

A portable, generic toolchain for analyzing stream ciphers: randomness testing
(NIST SP 800-22, TESTU01), linear complexity, statistical analysis, structural
attacks (algebraic/cube/correlation/distinguishing), forward/backward security,
provable-security and post-quantum scaffolding, and performance comparison.
"""

__version__ = "0.1.0"
__all__ = ["ingest", "linear", "stats"]
