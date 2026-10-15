#!/usr/bin/env python3
"""passcheck - estimate how strong a password is and explain why.

Method (deliberately simple and explainable):
  1. Work out the character pool the password draws from (lower, upper,
     digits, symbols, other).
  2. Discount characters that add almost no information: repeated runs
     ("aaaa"), sequences ("abc", "321"), keyboard walks ("qwerty") and the
     predictable start of a year ("2024").
  3. Estimate entropy as  effective_length * log2(pool_size).
  4. Cap the result if the password is a known common password, a common word
     with leetspeak ("p@ssw0rd"), or a common word with a trivial suffix.
  5. Turn the entropy into a 0-100 score, a rating and a rough crack time.

This is an educational estimate, not a guarantee. Real attackers use smarter
guessing than a pure entropy model.

The password is read with getpass (not echoed, not stored in shell history).
It is never written to disk or sent anywhere.
"""
from __future__ import annotations

import argparse
import getpass
import json
import math
import re
import string
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

__version__ = "1.0.0"

# A small built-in sample of very common passwords. Use --wordlist to load a
# larger list (for example a public "top 10,000" list).
COMMON_PASSWORDS = frozenset(
    """
    123456 password 123456789 12345678 12345 qwerty abc123 111111 1234567
    iloveyou admin welcome monkey login letmein dragon passw0rd master
    sunshine princess football baseball shadow superman trustno1 michael
    jennifer hunter buster soccer harley batman andrew tigger charlie
    robert thomas hockey ranger daniel starwars klaster 112233 george
    computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313
    freedom 777777 pass maggie 159753 aaaaaa ginger princess joshua cheese
    amanda summer love ashley nicole chelsea biteme matthew access yankees
    987654321 dallas austin thunder taylor matrix mobilemail mom monitor
    monitoring montana moon moscow secret hello whatever qazwsx 1q2w3e4r
    1qaz2wsx password1 password123 welcome1 admin123 letmein1 qwerty123
    changeme default guest root toor test test123 abcd1234 iloveyou1
    """.split()
)

LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

SEQUENCE_REFS = [
    string.ascii_lowercase,
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Assumed attacker speed against a fast offline hash: 10 billion guesses/second.
GUESSES_PER_SECOND = 1e10


@dataclass
class Result:
    length: int
    character_sets: list[str]
    pool_size: int
    effective_length: int
    entropy_bits: float
    score: int
    rating: str
    crack_time: str
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Analysis helpers
# --------------------------------------------------------------------------


def character_pool(password: str) -> tuple[int, list[str]]:
    """Return (pool size, names of the character sets used)."""
    sets: list[str] = []
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        sets.append("lowercase")
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        sets.append("uppercase")
        size += 26
    if any(c in string.digits for c in password):
        sets.append("digits")
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        sets.append("symbols")
        size += 33
    if any(ord(c) > 127 for c in password):
        sets.append("other")
        size += 64
    return size, sets


def _mark_repeats(pw: str, redundant: set[int]) -> bool:
    found = False
    i = 0
    while i < len(pw):
        j = i
        while j + 1 < len(pw) and pw[j + 1] == pw[i]:
            j += 1
        if j - i + 1 >= 3:
            redundant.update(range(i + 1, j + 1))
            found = True
        i = j + 1
    return found


def _mark_sequences(low: str, redundant: set[int]) -> list[str]:
    """Find runs such as abc, 321 or qwerty. Returns the runs found."""
    runs: list[str] = []
    for ref in SEQUENCE_REFS:
        for ref_s in (ref, ref[::-1]):
            i = 0
            while i < len(low):
                j = i
                while j + 1 < len(low) and low[i : j + 2] in ref_s:
                    j += 1
                if j - i + 1 >= 3:
                    redundant.update(range(i + 1, j + 1))
                    runs.append(low[i : j + 1])
                    i = j + 1
                else:
                    i += 1
    return runs


def _common_match(pw: str, common: frozenset[str]) -> str | None:
    """Classify how the password relates to the common-password list."""
    low = pw.lower()
    if low in common:
        return "exact"
    if low.translate(LEET_MAP) in common:
        return "leet"
    # Strip trailing digits/symbols first, so "summer2024!" is seen as "summer".
    stripped = re.sub(r"[\d\W_]+$", "", low)
    if stripped and stripped != low and (stripped in common or stripped.translate(LEET_MAP) in common):
        return "suffix"
    return None


# Diceware uses a 7,776-word list, so each randomly chosen word is ~12.9 bits.
BITS_PER_RANDOM_WORD = math.log2(7776)


def passphrase_words(pw: str) -> int:
    """Number of words if the password looks like a passphrase, else 0."""
    parts = [x for x in re.split(r"[\s\-_.]+", pw) if x]
    if len(parts) >= 3 and all(x.isalpha() and len(x) >= 3 for x in parts):
        return len(parts)
    return 0


def format_crack_time(bits: float) -> str:
    """Rough average time to crack at GUESSES_PER_SECOND."""
    if bits <= 0:
        return "instantly"
    seconds = (2**bits) / 2 / GUESSES_PER_SECOND
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365), ("year", 1000)]
    value = seconds
    for name, step in units:
        if value < step:
            n = int(value)
            return f"about {n} {name}{'' if n == 1 else 's'}"
        value /= step
    if value < 1e6:
        return f"about {int(value):,} thousand years"
    return "millions of years or more"


RATINGS = [(28, "Very weak"), (36, "Weak"), (60, "Reasonable"), (80, "Strong"), (math.inf, "Very strong")]
RATING_ORDER = [r for _, r in RATINGS]


def _rating(bits: float) -> str:
    for limit, name in RATINGS:
        if bits < limit:
            return name
    return RATINGS[-1][1]


# --------------------------------------------------------------------------
# Main analysis
# --------------------------------------------------------------------------


def analyse(password: str, common: frozenset[str] = COMMON_PASSWORDS) -> Result:
    if not password:
        raise ValueError("password is empty")

    pool, sets = character_pool(password)
    low = password.lower()
    redundant: set[int] = set()
    issues: list[str] = []
    suggestions: list[str] = []

    has_repeats = _mark_repeats(password, redundant)
    if has_repeats:
        issues.append("Contains repeated characters (e.g. 'aaa').")
    runs = _mark_sequences(low, redundant)
    if runs:
        shown = ", ".join(f"'{r}'" for r in runs[:3])
        issues.append(f"Contains predictable sequences or keyboard patterns: {shown}.")
    for m in re.finditer(r"(?:19|20)\d{2}", password):
        redundant.update({m.start(), m.start() + 1})
        issues.append(f"Contains a year ('{m.group()}'), which attackers try first.")
        break

    effective = len(password) - len(redundant)
    entropy = effective * math.log2(pool) if pool else 0.0

    words = passphrase_words(password)
    if words:
        # Character-level entropy badly overstates a passphrase made of real
        # words, so estimate by word count instead (assumes random word choice).
        entropy = min(entropy, words * BITS_PER_RANDOM_WORD)
        issues.append(
            f"Looks like a {words}-word passphrase, estimated at ~{BITS_PER_RANDOM_WORD:.1f} bits per word. "
            "This assumes the words were chosen randomly; a famous phrase, quote or lyric is far weaker."
        )

    match = _common_match(password, common)
    if match == "exact":
        entropy = 0.0
        issues.append("This is a very common password and would be guessed immediately.")
    elif match == "leet":
        entropy = min(entropy, 10.0)
        issues.append("This is a common password with letters swapped for symbols (e.g. a -> @). Attackers try these swaps.")
    elif match == "suffix":
        entropy = min(entropy, 20.0)
        issues.append("This is a common word with a few digits or symbols added to the end.")

    rating = _rating(entropy)
    if len(password) < 8:
        issues.append(f"Too short ({len(password)} characters).")
        if RATING_ORDER.index(rating) > RATING_ORDER.index("Weak"):
            rating = "Weak"

    score = max(0, min(100, round(entropy / 80 * 100)))
    if rating == "Very strong":
        score = max(score, 90)

    if len(password) < 12:
        suggestions.append("Use 12 or more characters. Length helps more than adding symbols.")
    if match or runs or has_repeats:
        suggestions.append("Avoid common words, sequences and repeats, even with substitutions.")
    suggestions.append("Try a passphrase of 5-6 randomly chosen, unrelated words; it is long, strong and memorable.")
    suggestions.append("Use a different password for every account, ideally stored in a password manager.")

    return Result(
        length=len(password),
        character_sets=sets,
        pool_size=pool,
        effective_length=effective,
        entropy_bits=round(entropy, 1),
        score=score,
        rating=rating,
        crack_time=format_crack_time(entropy),
        issues=issues,
        suggestions=suggestions,
    )


def load_wordlist(path: Path) -> frozenset[str]:
    with path.open(encoding="utf-8", errors="ignore") as fh:
        return frozenset(line.strip().lower() for line in fh if line.strip())


def render(result: Result) -> str:
    bar_len = 20
    filled = round(result.score / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)
    lines = [
        f"Rating        : {result.rating}  [{bar}] {result.score}/100",
        f"Length        : {result.length} characters ({result.effective_length} effective)",
        f"Character sets: {', '.join(result.character_sets) or 'none'}",
        f"Entropy       : ~{result.entropy_bits} bits",
        f"Crack time    : {result.crack_time} (offline attack, 10 billion guesses/sec)",
    ]
    if result.issues:
        lines += ["", "Issues:"] + [f"  - {i}" for i in result.issues]
    lines += ["", "Suggestions:"] + [f"  - {s}" for s in result.suggestions]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Estimate password strength and explain the result.")
    p.add_argument("--stdin", action="store_true", help="read the password from standard input instead of prompting")
    p.add_argument("--wordlist", type=Path, help="extra common-password list, one per line")
    p.add_argument("--json", action="store_true", help="output the result as JSON")
    args = p.parse_args(argv)

    common = COMMON_PASSWORDS
    if args.wordlist:
        if not args.wordlist.is_file():
            print(f"error: wordlist not found: {args.wordlist}", file=sys.stderr)
            return 2
        common = COMMON_PASSWORDS | load_wordlist(args.wordlist)

    password = sys.stdin.readline().rstrip("\n") if args.stdin else getpass.getpass("Password to check (hidden): ")
    try:
        result = analyse(password, common)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(result), indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
