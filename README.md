# passcheck: Password Strength Checker

A small, dependency-free Python command-line tool that estimates how strong a password is, **explains why**, and suggests how to improve it.

I built it to understand how password strength is actually measured, and why "complexity rules" like *one capital, one number, one symbol* are weaker guidance than length and unpredictability.

## Features

- Estimates entropy from the character pool and effective length
- Discounts predictable patterns: repeats (`aaaa`), sequences (`abc`, `321`), keyboard walks (`qwerty`), years (`2024`)
- Catches common passwords, leetspeak swaps (`P@ssw0rd`) and common words with trivial suffixes (`Summer2024!`)
- Handles passphrases separately, so long word-based passwords are not wildly overrated
- Gives a 0-100 score, a rating, a rough offline crack time and specific suggestions
- Optional bigger wordlist via `--wordlist`, and `--json` output
- The password is **never written to disk or sent anywhere**

## Usage

Requires Python 3.9+. Nothing to install.

```bash
python passcheck.py                       # prompts with hidden input
echo 'my-test-password' | python passcheck.py --stdin
python passcheck.py --wordlist top10000.txt
python passcheck.py --json
```

The password is deliberately **not** accepted as a command-line argument: arguments end up in shell history and process lists, which would be a bad habit for a security tool.

## Example output

Only throwaway test passwords are shown here.

```
$ echo 'Summer2024!' | python passcheck.py --stdin
Rating        : Very weak  [#####---------------] 25/100
Length        : 11 characters (9 effective)
Character sets: lowercase, uppercase, digits, symbols
Entropy       : ~20.0 bits
Crack time    : instantly (offline attack, 10 billion guesses/sec)

Issues:
  - Contains a year ('2024'), which attackers try first.
  - This is a common word with a few digits or symbols added to the end.

Suggestions:
  - Use 12 or more characters. Length helps more than adding symbols.
  - Avoid common words, sequences and repeats, even with substitutions.
  - Try a passphrase of 5-6 randomly chosen, unrelated words; it is long, strong and memorable.
  - Use a different password for every account, ideally stored in a password manager.
```

```
$ echo 'maple-river-stone-lantern-quiet-orbit' | python passcheck.py --stdin
Rating        : Strong  [###################-] 97/100
Length        : 37 characters (37 effective)
Character sets: lowercase, symbols
Entropy       : ~77.5 bits
Crack time    : about 350 thousand years (offline attack, 10 billion guesses/sec)

Issues:
  - Looks like a 6-word passphrase, estimated at ~12.9 bits per word. This assumes the words were chosen randomly; a famous phrase, quote or lyric is far weaker.

Suggestions:
  - Try a passphrase of 5-6 randomly chosen, unrelated words; it is long, strong and memorable.
  - Use a different password for every account, ideally stored in a password manager.
```

## How the score is calculated

1. **Character pool:** lowercase 26, uppercase 26, digits 10, symbols 33, other characters 64.
2. **Effective length:** characters that add almost no information (repeats, sequences, keyboard walks, the start of a year) are not counted.
3. **Entropy:** `effective_length x log2(pool_size)`.
4. **Caps:** exact common password = 0 bits; leetspeak version of a common password = 10 bits; common word plus trailing digits/symbols = 20 bits.
5. **Passphrases:** three or more separate words are estimated at about 12.9 bits per word (a 7,776-word Diceware list), assuming random choice.
6. **Rating:** under 28 bits Very weak, under 36 Weak, under 60 Reasonable, under 80 Strong, otherwise Very strong. Passwords under 8 characters cannot rate above Weak.
7. **Crack time:** average time at 10 billion guesses per second, a rough figure for an offline attack on a fast hash.

## Limitations (important)

- **It is an estimate, not a guarantee.** Real attackers use dictionaries, rules, leaked-password lists and personal information, not pure brute force.
- **The built-in common-password list is small.** A longer list catches much more. For example, `Tr0ub4dor&3` scores high with the built-in list only because "troubador" is not in it; add a wordlist containing it and it is caught.
- **The passphrase estimate assumes random word choice.** A famous quote, lyric or phrase is much weaker than the score suggests.
- It does not check whether a password has appeared in a known data breach. Services like Have I Been Pwned do that.
- Rules of thumb it reflects: length beats complexity, avoid patterns, use a unique password per account, and use a password manager.

## Tests

```bash
python -m unittest discover -s tests -v
```

20 unit tests cover character pools, each weakness detector, passphrase handling, custom wordlists, crack-time formatting and edge cases (empty input, Unicode).

## Ideas for next steps

- Check against the Have I Been Pwned range API using k-anonymity (only a hash prefix is sent)
- Detect dates, names and keyboard patterns with a larger pattern library
- Add a small web or GUI front end
- Compare the estimate with a standard library such as zxcvbn

## Licence

MIT
