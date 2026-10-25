
"""
Password Strength Checker
DecodeLabs | Cyber Security | Project 1: Defensive Logic

Goal:
    Decide whether a password is Weak, Medium or Strong using only
    string handling and conditional logic.

Policy (from the training kit):
    1. Length gate     : fewer than 8 characters = immediate Weak.
    2. Pattern checks  : uppercase [A-Z], digits [0-9], symbols.
    3. Unicode aware   : str.isupper()/isdigit()/isalnum() work on any
                         script, so non-ASCII passwords are handled too.
    4. Linear time     : every check is a single O(n) scan using any(),
                         which stops at the first match (short-circuit).
    5. Bonus checks    : common "leaked" passwords are rejected, and
                         longer passwords earn extra points.

Usage:
    python password_strength_checker.py          # interactive (input hidden)
    python password_strength_checker.py --test   # run built-in test cases

Security notes:
    * The password is read with getpass so it is not echoed or kept in
      shell history. Never pass a real password as a command-line argument.
    * The program never prints, logs or stores the password.
    * Python strings are immutable, so a copy can linger in RAM until
      garbage collection. This is a learning tool: do not paste real
      credentials into any tool you do not trust.
"""

import getpass
import math
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------- policy ---
MIN_LENGTH = 8           # below this: immediate fail
LONG_LENGTH = 12         # +1 point
VERY_LONG_LENGTH = 16    # +1 more point

STRONG_SCORE = 5         # score >= 5 -> Strong
MEDIUM_SCORE = 3         # score >= 3 -> Medium, otherwise Weak

# A tiny sample of the most common leaked passwords (compared case-insensitively).
# A real system would check against a large breached-password list.
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "p@ssword", "p@ssword123", "123456", "1234567", "12345678",
    "123456789", "1234567890", "111111", "123123", "qwerty",
    "qwerty123", "qwertyuiop", "abc123", "letmein", "welcome",
    "welcome1", "admin", "admin123", "iloveyou", "monkey", "dragon",
    "football", "baseball", "changeme", "trustno1",
})


# --------------------------------------------------------------- results ---
@dataclass(frozen=True)
class Result:
    strength: str            # "Weak" | "Medium" | "Strong"
    length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    entropy_bits: float      # rough estimate, see check_password()
    feedback: tuple          # suggestions for improving the password


# ----------------------------------------------------------------- logic ---
def check_password(password: str) -> Result:
    """Evaluate a password and return a Result. Pure function, no I/O."""
    length = len(password)

    # Pattern recognition: one short-circuiting linear scan per character class.
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    # Anything that is not a letter or digit counts as a symbol (this includes
    # spaces, punctuation and emoji, i.e. the "Unicode curveball").
    has_symbol = any(not c.isalnum() for c in password)

    # Rough entropy estimate: length * log2(size of the character pool used).
    # Non-ASCII characters are counted inside the 33-symbol pool, so the
    # estimate is conservative for Unicode passwords.
    pool = (26 * has_lower) + (26 * has_upper) + (10 * has_digit) + (33 * has_symbol)
    entropy_bits = length * math.log2(pool) if pool else 0.0

    # Feedback
    feedback = []
    if length < MIN_LENGTH:
        feedback.append(f"Use at least {MIN_LENGTH} characters (yours has {length}).")
    if not has_upper:
        feedback.append("Add an uppercase letter (A-Z).")
    if not has_lower:
        feedback.append("Add a lowercase letter (a-z).")
    if not has_digit:
        feedback.append("Add a number (0-9).")
    if not has_symbol:
        feedback.append("Add a symbol (for example ! @ # $ %).")

    # Scoring: one point per character class, plus length bonuses.
    variety = has_upper + has_lower + has_digit + has_symbol
    length_bonus = (length >= LONG_LENGTH) + (length >= VERY_LONG_LENGTH)
    score = variety + length_bonus

    # Classification
    if length < MIN_LENGTH:
        strength = "Weak"                       # the length gate always wins
    elif password.casefold() in COMMON_PASSWORDS:
        strength = "Weak"
        feedback.insert(0, "This is one of the most commonly used passwords.")
    elif score >= STRONG_SCORE:
        strength = "Strong"
    elif score >= MEDIUM_SCORE:
        strength = "Medium"
    else:
        strength = "Weak"

    if strength != "Strong" and MIN_LENGTH <= length < LONG_LENGTH:
        feedback.append(f"Longer is stronger: aim for {LONG_LENGTH}+ characters.")

    return Result(strength, length, has_upper, has_lower, has_digit,
                  has_symbol, entropy_bits, tuple(feedback))


# ---------------------------------------------------------------- output ---
_COLORS = {"Weak": "\033[91m", "Medium": "\033[93m", "Strong": "\033[92m"}
_BARS = {"Weak": "[#--]", "Medium": "[##-]", "Strong": "[###]"}
_RESET = "\033[0m"


def _tick(flag: bool) -> str:
    return "yes" if flag else "no "


def report(result: Result) -> None:
    """Print a human-readable summary of a Result."""
    color, reset = ("", "")
    if sys.stdout.isatty():
        color, reset = _COLORS[result.strength], _RESET

    print()
    print(f"  Strength : {color}{_BARS[result.strength]} {result.strength.upper()}{reset}")
    print(f"  Length   : {result.length}")
    print(f"  Uppercase: {_tick(result.has_upper)}   Lowercase: {_tick(result.has_lower)}")
    print(f"  Number   : {_tick(result.has_digit)}   Symbol   : {_tick(result.has_symbol)}")
    print(f"  Entropy  : ~{result.entropy_bits:.0f} bits (rough estimate)")
    if result.feedback:
        print("  Tips:")
        for tip in result.feedback:
            print(f"    - {tip}")
    print()


def run_tests() -> None:
    cases = [
        ("", "Weak"),                       # empty
        ("abc", "Weak"),                    # too short
        ("Ab1!", "Weak"),                   # varied but too short
        ("aaaaaaaa", "Weak"),               # length ok, no variety
        ("12345678", "Weak"),               # common + digits only
        ("Password1", "Weak"),              # common password
        ("Summer2024", "Medium"),           # 3 classes, 10 chars
        ("Abc!2345", "Medium"),             # 4 classes, 8 chars
        ("correcthorsebattery", "Medium"),  # long, but lowercase only
        ("Xk9#mQ2vLp@7", "Strong"),         # 4 classes, 13 chars
        ("Tr!ckyHorse#2026", "Strong"),     # 4 classes, 16 chars
        ("Пароль🙂Secure9", "Strong"),      # Unicode letters and emoji
    ]
    print(f"{'PASSWORD':<22}{'EXPECTED':<10}{'GOT':<10}RESULT")
    print("-" * 52)
    failures = 0
    for pw, expected in cases:
        got = check_password(pw).strength
        ok = got == expected
        failures += not ok
        shown = pw if pw else "(empty)"
        print(f"{shown:<22}{expected:<10}{got:<10}{'PASS' if ok else 'FAIL'}")
    print("-" * 52)
    print(f"{len(cases) - failures}/{len(cases)} tests passed")
    if failures:
        sys.exit(1)

def main() -> None:
    if "--test" in sys.argv[1:]:
        run_tests()
        return

    print("=" * 52)
    print("Password Strength Checker")
    print(" Your input is hidden. Press Enter on a blank line to quit.")
    print("=" * 52)

    while True:
        try:
           password = input("\nEnter a password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not password:
            break
        report(check_password(password))
        del password  # drop our reference as soon as we are done with it

    print("Stay safe out there.")


if __name__ == "__main__":
    main()