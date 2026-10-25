# Password Strength Checker

A small Python command-line project that classifies a password as **Weak**,
**Medium**, or **Strong** using character variety, length, and a small sample
of commonly used passwords. It is a learning tool, not a replacement for a
production password-strength or breached-password service.

## Requirements

- Python 3.7 or newer

The project uses only Python's standard library.

## Run

```powershell
python password_strength_checker.py
```

Enter a password when prompted. The current program uses ordinary terminal
input, so the characters you type are visible on screen. Do not enter a real
or reused password.

Run the built-in checks with:

```powershell
python password_strength_checker.py --test
```

## How scoring works

- Passwords shorter than 8 characters are always **Weak**.
- One point is awarded for each character class present: uppercase letters,
  lowercase letters, digits, and symbols.
- Passwords of 12 or more characters get one length point; passwords of 16 or
  more get a second.
- A score of 3–4 is **Medium**; a score of 5 or more is **Strong**.
- Passwords in a small built-in common-password sample are rejected as
  **Weak** (case-insensitively).
- The displayed entropy is a rough estimate based on the observed character
  classes. It is not a guarantee of how difficult a password is to guess.

Character-class checks use Python's Unicode-aware string methods. Any
character that is not alphanumeric—including whitespace and emoji—counts as a
symbol.

## Security notes

- The checker does not print, log, or store the entered password itself, but
  terminal input is visible while typing.
- Its common-password sample is intentionally small and is not a comprehensive
  breached-password check.
- Do not use this educational tool to assess or handle real account passwords.
