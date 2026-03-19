#!/usr/bin/env python3
"""
password-auditor — audit.py
Cracks hashed passwords against a wordlist, scores strength,
and outputs a coloured terminal report, HTML report, and CSV export.

Usage:
    python audit.py -f hashes.txt -w wordlist.txt
    python audit.py -f hashes.txt -w wordlist.txt --algo sha256
    python audit.py -f hashes.txt -w wordlist.txt --html report.html --csv results.csv
    python audit.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

Supported algorithms: md5, sha1, sha256, sha512, ntlm
"""

import argparse
import csv
import hashlib
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path


# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GREY   = "\033[90m"

def c(text, colour):
    return f"{colour}{text}{RESET}"

def banner():
    print(f"""
{CYAN}{BOLD}
 ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
 ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
 ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
 ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
 ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝
{RESET}{GREY}  ╔═══════════════════════════════════════════════════════════╗
  ║  Password Audit Tool  ·  github.com/Evidence05             ║
  ║  For authorised security testing only                      ║
  ╚═══════════════════════════════════════════════════════════╝{RESET}
""")


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_word(word: str, algo: str) -> str:
    word_bytes = word.encode("utf-8")
    if algo == "md5":
        return hashlib.md5(word_bytes).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word_bytes).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word_bytes).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(word_bytes).hexdigest()
    elif algo == "ntlm":
        import hashlib as _hl
        return _hl.new("md4", word.encode("utf-16-le")).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")


def detect_algo(hash_str: str) -> str:
    length = len(hash_str)
    mapping = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    return mapping.get(length, "unknown")


# ── Strength scoring ──────────────────────────────────────────────────────────

def score_password(password: str) -> dict:
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (< 8 chars)")

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("No uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("No lowercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("No digits")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
    else:
        feedback.append("No special characters")

    common = ["password", "123456", "qwerty", "letmein", "admin", "welcome",
              "monkey", "dragon", "master", "abc123", "iloveyou", "sunshine"]
    if password.lower() in common:
        score = 1
        feedback.append("Extremely common password")

    if score <= 2:
        label, colour = "VERY WEAK", RED
    elif score == 3:
        label, colour = "WEAK", RED
    elif score == 4:
        label, colour = "MODERATE", YELLOW
    elif score == 5:
        label, colour = "STRONG", GREEN
    else:
        label, colour = "VERY STRONG", GREEN

    return {"score": score, "max": 6, "label": label, "colour": colour, "feedback": feedback}


# ── Core audit ────────────────────────────────────────────────────────────────

def load_hashes(path: str) -> list[str]:
    with open(path, "r") as f:
        return [line.strip().lower() for line in f if line.strip()]


def load_wordlist(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\n")
            if word:
                yield word


def run_audit(hashes: list, wordlist_path: str, algo: str) -> list[dict]:
    results = {h: {"hash": h, "password": None, "cracked": False, "strength": None} for h in hashes}
    remaining = set(hashes)
    total_words = 0
    start = time.time()

    print(f"\n{BOLD}  [{c('*', CYAN)}] Starting audit{RESET}")
    print(f"  {DIM}Algorithm : {algo.upper()}{RESET}")
    print(f"  {DIM}Hashes    : {len(hashes)}{RESET}")
    print(f"  {DIM}Wordlist  : {wordlist_path}{RESET}\n")

    try:
        for word in load_wordlist(wordlist_path):
            total_words += 1
            candidate = hash_word(word, algo)

            if candidate in remaining:
                remaining.remove(candidate)
                strength = score_password(word)
                results[candidate]["password"] = word
                results[candidate]["cracked"] = True
                results[candidate]["strength"] = strength

                bar = "█" * strength["score"] + "░" * (6 - strength["score"])
                print(f"  {c('✔', GREEN)} {c(candidate[:16] + '...', GREY)}  →  "
                      f"{c(word, WHITE)}  "
                      f"[{c(bar, strength['colour'])}] "
                      f"{c(strength['label'], strength['colour'])}")

                if not remaining:
                    break

            if total_words % 100000 == 0:
                elapsed = time.time() - start
                speed = total_words / elapsed if elapsed > 0 else 0
                print(f"  {GREY}  {total_words:,} words checked · {speed:,.0f} w/s · "
                      f"{len(hashes) - len(remaining)}/{len(hashes)} cracked{RESET}")

    except KeyboardInterrupt:
        print(f"\n  {YELLOW}[!] Interrupted by user{RESET}")

    elapsed = time.time() - start
    cracked_count = len(hashes) - len(remaining)

    print(f"\n  {DIM}─────────────────────────────────────────────────────{RESET}")
    print(f"  {BOLD}Results{RESET}")
    print(f"  Checked   : {c(f'{total_words:,}', CYAN)} words in {elapsed:.2f}s "
          f"({c(f'{total_words/elapsed:,.0f} w/s', GREY)})")
    print(f"  Cracked   : {c(str(cracked_count), GREEN if cracked_count else GREY)} / {len(hashes)}")
    print(f"  Failed    : {c(str(len(remaining)), RED if remaining else GREY)}")

    if remaining:
        print(f"\n  {YELLOW}[!] Uncracked hashes:{RESET}")
        for h in remaining:
            print(f"      {GREY}{h}{RESET}")

    # strength summary
    cracked = [r for r in results.values() if r["cracked"]]
    if cracked:
        print(f"\n  {BOLD}Strength Breakdown{RESET}")
        from collections import Counter
        labels = Counter(r["strength"]["label"] for r in cracked)
        for label, count in sorted(labels.items()):
            col = GREEN if "STRONG" in label else (YELLOW if "MODERATE" in label else RED)
            bar = "█" * count
            print(f"  {c(f'{label:<12}', col)}  {bar}  {count}")

    print(f"  {DIM}─────────────────────────────────────────────────────{RESET}\n")

    return list(results.values())


# ── HTML report ───────────────────────────────────────────────────────────────

def write_html(results: list, algo: str, path: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cracked = [r for r in results if r["cracked"]]
    uncracked = [r for r in results if not r["cracked"]]

    def strength_badge(s):
        if not s:
            return ""
        colours = {"VERY WEAK": "#f85149", "WEAK": "#f85149",
                   "MODERATE": "#e3b341", "STRONG": "#3fb950", "VERY STRONG": "#3fb950"}
        col = colours.get(s["label"], "#888")
        bar = "█" * s["score"] + "░" * (6 - s["score"])
        return f'<span style="color:{col};font-family:monospace">{bar}</span> <span class="badge" style="background:{col}22;color:{col};border:1px solid {col}44">{s["label"]}</span>'

    rows = ""
    for r in results:
        status = '<span class="badge cracked">CRACKED</span>' if r["cracked"] else '<span class="badge uncracked">NOT FOUND</span>'
        pw = f'<code>{r["password"]}</code>' if r["password"] else '<span style="color:#555">—</span>'
        sb = strength_badge(r.get("strength")) if r["cracked"] else ""
        rows += f"""
        <tr>
            <td><code class="hash">{r['hash']}</code></td>
            <td>{status}</td>
            <td>{pw}</td>
            <td>{sb}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Audit Report</title>
<style>
  :root {{ --bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e; }}
  * {{ box-sizing:border-box;margin:0;padding:0; }}
  body {{ background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:40px; }}
  h1 {{ font-size:22px;color:#fff;margin-bottom:4px; }}
  .meta {{ color:var(--muted);font-size:13px;margin-bottom:32px; }}
  .stats {{ display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px; }}
  .stat {{ background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 20px; }}
  .stat-label {{ font-size:11px;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:8px; }}
  .stat-value {{ font-size:28px;font-weight:bold; }}
  table {{ width:100%;border-collapse:collapse;font-size:13px; }}
  th {{ padding:10px 14px;text-align:left;color:var(--muted);font-size:11px;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid var(--border);background:#ffffff04; }}
  td {{ padding:10px 14px;border-bottom:1px solid #30363d55;vertical-align:middle; }}
  tr:hover td {{ background:#ffffff04; }}
  code {{ color:#7ec8ff; }}
  .hash {{ font-size:11px;color:#8b949e; }}
  .badge {{ display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold; }}
  .cracked {{ background:#3fb95022;color:#3fb950;border:1px solid #3fb95044; }}
  .uncracked {{ background:#f8514922;color:#f85149;border:1px solid #f8514944; }}
  .footer {{ color:var(--muted);font-size:12px;margin-top:32px;text-align:center; }}
</style>
</head>
<body>
<h1>🔍 Password Audit Report</h1>
<div class="meta">Generated: {now} &nbsp;·&nbsp; Algorithm: {algo.upper()} &nbsp;·&nbsp; Total hashes: {len(results)}</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Total</div><div class="stat-value" style="color:#c9d1d9">{len(results)}</div></div>
  <div class="stat"><div class="stat-label">Cracked</div><div class="stat-value" style="color:#3fb950">{len(cracked)}</div></div>
  <div class="stat"><div class="stat-label">Not Found</div><div class="stat-value" style="color:#f85149">{len(uncracked)}</div></div>
  <div class="stat"><div class="stat-label">Crack Rate</div><div class="stat-value" style="color:#e3b341">{len(cracked)/len(results)*100:.0f}%</div></div>
</div>
<table>
  <thead><tr><th>Hash</th><th>Status</th><th>Password</th><th>Strength</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<div class="footer">password-auditor · github.com/Evidence05 · For authorised use only</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"  {c('✔', GREEN)} HTML report saved → {path}")


# ── CSV export ────────────────────────────────────────────────────────────────

def write_csv(results: list, algo: str, path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["hash", "algorithm", "cracked", "password", "strength_score", "strength_label", "feedback"])
        for r in results:
            s = r.get("strength") or {}
            writer.writerow([
                r["hash"], algo,
                r["cracked"],
                r["password"] or "",
                s.get("score", ""),
                s.get("label", ""),
                "; ".join(s.get("feedback", [])),
            ])
    print(f"  {c('✔', GREEN)} CSV export saved  → {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Password Audit Tool — crack hashes and score password strength",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python audit.py -f hashes.txt -w wordlist.txt
  python audit.py -f hashes.txt -w wordlist.txt --algo sha256
  python audit.py -f hashes.txt -w wordlist.txt --html report.html --csv out.csv
  python audit.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
        """
    )
    parser.add_argument("-f", "--file", help="File containing hashes (one per line)")
    parser.add_argument("--hash", help="Single hash to crack")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")
    parser.add_argument("--algo", default="auto",
                        choices=["auto", "md5", "sha1", "sha256", "sha512", "ntlm"],
                        help="Hash algorithm (default: auto-detect)")
    parser.add_argument("--html", metavar="FILE", help="Save HTML report to FILE")
    parser.add_argument("--csv",  metavar="FILE", help="Save CSV export to FILE")

    args = parser.parse_args()

    if not args.file and not args.hash:
        parser.error("Provide --file or --hash")

    if not os.path.exists(args.wordlist):
        print(f"{RED}[!] Wordlist not found: {args.wordlist}{RESET}")
        sys.exit(1)

    banner()

    # load hashes
    if args.file:
        if not os.path.exists(args.file):
            print(f"{RED}[!] Hash file not found: {args.file}{RESET}")
            sys.exit(1)
        hashes = load_hashes(args.file)
    else:
        hashes = [args.hash.strip().lower()]

    # detect algorithm
    algo = args.algo
    if algo == "auto":
        algo = detect_algo(hashes[0])
        if algo == "unknown":
            print(f"{RED}[!] Could not detect algorithm from hash length. Use --algo to specify.{RESET}")
            sys.exit(1)
        print(f"  {GREY}[i] Auto-detected algorithm: {algo.upper()}{RESET}")

    results = run_audit(hashes, args.wordlist, algo)

    if args.html:
        write_html(results, algo, args.html)

    if args.csv:
        write_csv(results, algo, args.csv)

    if args.html or args.csv:
        print()


if __name__ == "__main__":
    main()
