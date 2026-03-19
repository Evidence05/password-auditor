# 🔍 Password Audit Tool

A command-line tool that audits password security by cracking hashed passwords against a wordlist, scoring each recovered password's strength, and generating reports in terminal, HTML, and CSV formats.

Built as part of a cybersecurity portfolio. demonstrating knowledge of hashing algorithms, dictionary attacks, and password security assessment.

---

## Features

- **Dictionary attack** against MD5, SHA-1, SHA-256, SHA-512, and NTLM hashes
- **Auto-detects** hash algorithm from hash length
- **Strength scoring** rates each cracked password across 6 criteria (length, complexity, character classes, commonality)
- **Coloured terminal output** with live progress and speed metrics
- **HTML report** clean dark-themed report with strength breakdowns
- **CSV export** structured output for further analysis
- Single hash mode or bulk file mode

---

## Usage

```bash
# Basic — auto-detect algorithm
python audit.py -f hashes.txt -w wordlist.txt

# Specify algorithm
python audit.py -f hashes.txt -w wordlist.txt --algo sha256

# All outputs
python audit.py -f hashes.txt -w wordlist.txt --html report.html --csv results.csv

# Single hash
python audit.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
```

---

## Supported Algorithms

| Algorithm | Hash Length |
|-----------|------------|
| MD5       | 32 chars   |
| SHA-1     | 40 chars   |
| SHA-256   | 64 chars   |
| SHA-512   | 128 chars  |
| NTLM      | 32 chars (specify with `--algo ntlm`) |

---

## Quick Demo

```bash
# Run against included sample files
python audit.py -f sample_hashes.txt -w sample_wordlist.txt --html report.html --csv results.csv
```

Sample hashes included are MD5s of common passwords for demonstration purposes.

---

## Strength Scoring

Each recovered password is scored out of 6:

| Criteria | Points |
|----------|--------|
| Length ≥ 8 | +1 |
| Length ≥ 12 | +1 |
| Uppercase letters | +1 |
| Lowercase letters | +1 |
| Digits | +1 |
| Special characters | +1 |

| Score | Rating |
|-------|--------|
| 1–2 | VERY WEAK |
| 3 | WEAK |
| 4 | MODERATE |
| 5 | STRONG |
| 6 | VERY STRONG |

---

## Wordlists

The included `sample_wordlist.txt` is for demo only. For real audits, use:
- [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

---

## Requirements

Python 3.10+ — no external dependencies, standard library only.

---

## Disclaimer

This tool is intended for **authorised security testing only** — auditing your own systems, CTF challenges, or environments you have explicit permission to test. Do not use against systems or accounts you do not own or have permission to test.

---

## Author

**Ali Sadulla** — [linkedin.com/in/ali-h-sadulla-a1332928a](https://linkedin.com/in/ali-h-sadulla-a1332928a) · [evidence05.github.io](https://evidence05.github.io)
