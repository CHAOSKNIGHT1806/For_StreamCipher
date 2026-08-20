"""NIST SP 800-22 Rev 1a — standard constants (transcribed from authoritative source).

All constants below are transcribed from the NIST Statistical Test Suite (STS) 2.1.2
reference implementation, which NIST distributed alongside SP 800-22 Rev 1a.  NIST
withdrew SP 800-22 in November 2022, so these values are kept only for compatibility
with the stream-cipher literature; see the note in ``rng_nist.py``.

Primary sources (cross-checked against two independent ports that reproduce the same
values byte-for-byte):

  * NIST STS 2.1.2 C source, files
      - ``src/nonOverlappingTemplateMatchings.c``  (``numOfTemplates[9] = 148``)
      - ``templates/template9``                      (the 148 m=9 bit patterns)
      - ``src/randomExcursions.c``                   (``double pi[5][6]`` table)
      - ``src/randomExcursionsVariant.c``            (closed-form statistic)
    bundled verbatim in the `honno/sts-pylib` mirror
    (https://github.com/honno/sts-pylib), which states: "This package wraps the
    statistical tests written in C from *sts*, ... an implementation ... recommended
    in the *SP800-22* paper".

  * ``nistrng`` 1.2.3 (PyPI) — pure-Python port of SP 800-22 Rev 1a
    (https://pypi.org/project/nistrng/), files ``test_non_overlapping_template_matching.py``,
    ``test_random_excursion.py``, ``test_random_excursion_variant.py``.

  * ``dj-on-github/sp800_22_tests`` (https://github.com/dj-on-github/sp800_22_tests) —
    ``sp800_22_non_overlapping_template_matching_test.py``,
    ``sp800_22_random_excursion_test.py``, ``sp800_22_random_excursion_variant_test.py``.

  * Rust crate ``nistrs`` (https://docs.rs/nistrs) — direct transcription of the NIST C code.

IMPORTANT clarifications versus a naive reading of the standard:

1. ``TEMPLATES_M9`` — the 148 non-periodic 9-bit templates NIST uses for the
   Non-overlapping Template Matching test (SP 800-22 §2.7).  These are *not* all 512
   9-bit patterns; they are the specific 148 aperiodic patterns read from
   ``templates/template9``.  Each is given as an integer whose 9-bit big-endian
   binary expansion equals the bit pattern (bit 0 = MSB = first bit of the template).

2. ``EXCURSIONS_PIX`` — the Random Excursions test (SP 800-22 §2.14) uses a table of
   probabilities ``pi(|x|, k)`` indexed by the *absolute* state value |x| ∈ {1,2,3,4}
   and the visit count k ∈ {0,1,2,3,4,>=5}, i.e. SIX values per |x|.  The eight states
   x = -4,-3,-2,-1,+1,+2,+3,+4 all share ``pi(|x|, k)``.  There is *no* single ``pi_x``
   value per state in the standard.  ``EXCURSIONS_PIX`` holds the full NIST ``pi[5][6]``
   table (row |x| = 1..4; the C array's row 0 is an unused zero placeholder).  The
   values here are NIST's full-precision transcriptions (not the 4-decimal rounded
   versions seen in some ports).

3. ``EXCURSIONS_VARIANT_*`` — the Random Excursions Variant test (SP 800-22 §2.15) does
   NOT use a per-state (expected J, std) *lookup table* in the NIST implementation.  The
   statistic is computed in closed form from the number of cycles J:

       E[ xi(x) ] = J                                (expected visits to state x)
       std         = sqrt( 2 * J * (4*|x| - 2) )     (standard deviation)

   The p-value is ``erfc( |count(x) - J| / sqrt(2*J*(4*|x|-2)) )``
   (see ``randomExcursionsVariant.c`` line 51).  We therefore expose the *per-|x|*
   multiplicative coefficient ``4*|x| - 2`` (so std = sqrt(2*J*coeff)) as
   ``EXCURSIONS_VARIANT_COEFF`` rather than fabricating a table that does not exist in
   the standard.
"""

# --------------------------------------------------------------------------- #
# Non-overlapping Template Matching (§2.7): templates/template9 (m = 9)
# Source: NIST STS 2.1.2 ``templates/template9`` (148 lines), referenced by
# ``src/nonOverlappingTemplateMatchings.c`` ``numOfTemplates[9] = 148``.
# Integers are the big-endian (MSB-first) bit patterns.
# --------------------------------------------------------------------------- #
TEMPLATES_M9 = [
    # block 1 (leading 00000000)
    1,      3,      5,      7,      9,      11,     13,     15,
    17,     19,     21,     23,     25,     27,     29,     31,
    # block 2 (leading 00000001)
    35,     37,     39,     41,     43,     45,     47,      51,
    53,     55,     57,     59,     61,     63,
    # block 3 (leading 00000010)
    67,     69,     71,     75,     77,     79,     83,     85,
    87,     91,     93,     95,
    # block 4 (leading 00000011)
    101,    103,    107,    109,    111,    117,    119,    123,
    125,    127,
    # block 5 (leading 00000100)
    131,    135,    139,    143,    147,    151,    155,    159,
    # block 6 (leading 00000101)
    163,    167,    171,    175,    179,    183,    187,    191,
    # block 7 (leading 00000110)
    199,    207,    215,    223,
    # block 8 (leading 00000111)
    239,    255,
    # block 9 (leading 00001000)
    256,    272,    288,    296,    304,    312,    320,    324,
    328,    332,    336,    340,    344,    348,    352,    356,
    360,    364,    368,    372,    376,    380,
    # block 10 (leading 00001001)
    384,    386,    388,    392,    394,    400,    402,    404,
    408,    410,    416,    418,    420,    424,    426,    428,
    432,    434,    436,    440,    442,    444,
    # block 11 (leading 00001010)
    448,    450,    452,    454,    456,    458,    460,    464,
    466,    468,    470,    472,    474,    476,
    # block 12 (leading 00001011)
    480,    482,    484,    486,    488,    490,    492,    494,
    496,    498,    500,    502,    504,    506,    508,    510,
]

assert len(TEMPLATES_M9) == 148, f"expected 148 templates, got {len(TEMPLATES_M9)}"
assert len(set(TEMPLATES_M9)) == 148, "templates must be unique"

# For callers that prefer 9-character bit-strings (bit 0 = first bit of the pattern).
TEMPLATES_M9_STR = [f"{v:09b}" for v in TEMPLATES_M9]


# --------------------------------------------------------------------------- #
# Random Excursions (§2.14): pi(|x|, k) — probability that state x occurs k times
# in a cycle, for |x| = 1..4 and k = 0,1,2,3,4,>=5.
# Source: NIST STS 2.1.2 ``src/randomExcursions.c``, ``double pi[5][6]`` (full
# precision).  Row 0 of the C array is an unused zero placeholder; omitted here.
# --------------------------------------------------------------------------- #
EXCURSIONS_PIX = {
    # |x|: [ pi(k=0), pi(k=1), pi(k=2), pi(k=3), pi(k=4), pi(k>=5) ]
    1: [0.5,         0.25,        0.125,       0.0625,       0.03125,     0.03125],
    2: [0.75,        0.0625,      0.046875,    0.03515625,   0.0263671875, 0.0791015625],
    3: [0.8333333333, 0.02777777778, 0.02314814815, 0.01929012346, 0.01607510288, 0.0803755143],
    4: [0.875,       0.015625,    0.013671875,  0.01196289063, 0.01046752930, 0.0732727051],
}

# The eight excursion states; each maps to pi row `abs(x)` above.
EXCURSION_STATES = [-4, -3, -2, -1, 1, 2, 3, 4]


# --------------------------------------------------------------------------- #
# Random Excursions Variant (§2.15): closed-form statistic (no lookup table).
# Source: NIST STS 2.1.2 ``src/randomExcursionsVariant.c`` (line 51), which uses
#   p_value = erfc( |count(x) - J| / sqrt( 2.0 * J * (4.0 * |x| - 2) ) )
# The expected number of visits to state x is J (the number of cycles); the
# standard deviation is sqrt( 2 * J * (4*|x| - 2) ).
# --------------------------------------------------------------------------- #
#: coefficient (4*|x| - 2) so that std = sqrt(2 * J * coeff[|x|]).
EXCURSIONS_VARIANT_COEFF = {abs(x): 4 * abs(x) - 2 for x in range(-9, 10) if x != 0}

_EXCURSIONS_VARIANT_STATES = [x for x in range(-9, 10) if x != 0]

#: Expected value of the visit count for each state, expressed in terms of J.
#: J (number of cycles) is sequence-dependent, so it cannot be a fixed constant;
#: this documents the closed form rather than inventing a table.
EXCURSIONS_VARIANT_EXPECTED = {
    x: ("J", None) for x in _EXCURSIONS_VARIANT_STATES
}

#: Standard deviation of the visit count for each state, in terms of J:
#:   std(|x|) = sqrt( 2 * J * (4*|x| - 2) )
#: stored as the (coeff, formula) so callers can compute it from J.
EXCURSIONS_VARIANT_STD = {
    x: ("sqrt(2*J*(4*|x|-2))", 4 * abs(x) - 2) for x in _EXCURSIONS_VARIANT_STATES
}


__all__ = [
    "TEMPLATES_M9",
    "TEMPLATES_M9_STR",
    "EXCURSIONS_PIX",
    "EXCURSION_STATES",
    "EXCURSIONS_VARIANT_COEFF",
    "EXCURSIONS_VARIANT_EXPECTED",
    "EXCURSIONS_VARIANT_STD",
]
