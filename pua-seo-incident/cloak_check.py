#!/usr/bin/env python3
"""
cloak_check.py - read-only SEO-cloaking check for *.pua.edu.eg

Fetches each URL once per request variant (normal browser, Googlebot desktop,
Googlebot smartphone, Google-TH referral, Google-EG referral) and compares the
responses against the normal-browser baseline (variant A).

Safety rules built in:
  * GET only, allow_redirects=False, timeout=20s, 2-second delay between requests.
  * Location headers are recorded but NEVER followed.
  * Any URL whose host is not *.pua.edu.eg is refused.
  * Matched adult text is never printed, logged or saved: only booleans/counts.

Usage:
    python3 cloak_check.py [--out results]

IMPORTANT CAVEAT: many IIS cloaking modules (BADIIS / GhostRedirector-Gamshen)
verify Googlebot by source IP (reverse DNS / Google IP ranges). A request that
merely *claims* to be Googlebot from a non-Google IP will often get the clean
page. "No difference" from here does NOT mean the site is clean. Use Search
Console > URL Inspection > "Test live URL" / "View crawled page" for the
authoritative Googlebot view.
"""

import argparse
import csv
import hashlib
import html
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
GOOGLEBOT_DESKTOP = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GOOGLEBOT_SMARTPHONE = (
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 "
    "(compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

VARIANTS = {
    "A": {"label": "Chrome desktop", "headers": {"User-Agent": CHROME_UA}},
    "B": {"label": "Googlebot desktop", "headers": {"User-Agent": GOOGLEBOT_DESKTOP}},
    "C": {"label": "Googlebot smartphone", "headers": {"User-Agent": GOOGLEBOT_SMARTPHONE}},
    "D": {
        "label": "Chrome + google.co.th referer + th-TH",
        "headers": {
            "User-Agent": CHROME_UA,
            "Referer": "https://www.google.co.th/",
            "Accept-Language": "th-TH,th;q=0.9",
        },
    },
    "E": {
        "label": "Chrome + google.com.eg referer + ar-EG",
        "headers": {
            "User-Agent": CHROME_UA,
            "Referer": "https://www.google.com.eg/",
            "Accept-Language": "ar-EG,ar;q=0.9",
        },
    },
}

URLS = [
    ("target", "https://academic.pua.edu.eg/Account/Register"),
    ("target", "https://portal.pua.edu.eg/SelfService/Registration/RegistrationHome.aspx"),
    ("target", "https://portal.pua.edu.eg/SelfService/Login.aspx"),
    ("target", "https://portal.pua.edu.eg/SelfService/Home.aspx"),
    ("target", "https://portal.pua.edu.eg/SelfService/Search/SectionSearch.aspx"),
    ("target", "https://www.pua.edu.eg/"),
    ("target", "https://www.pua.edu.eg/?lang=ar"),
    ("target", "https://www.pua.edu.eg/student-area/"),
    ("control", "https://celta.pua.edu.eg/"),
    ("control", "https://blackboard.pua.edu.eg/"),
]

DELAY_SECONDS = 2
TIMEOUT = 20
MAX_BODY = 5 * 1024 * 1024  # never read more than 5 MB per response

THAI_RE = re.compile(r"[\u0E00-\u0E7F]")
CJK_RE = re.compile(r"[\u3040-\u30FF\u3400-\u4DBF\u4E00-\u9FFF\uAC00-\uD7AF\uF900-\uFAFF]")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Gambling terms: the term names are safe to report.
GAMBLING_TERMS = {
    "slot": re.compile(r"\bslots?\b", re.I),
    "casino": re.compile(r"\bcasino", re.I),
    "pg": re.compile(r"\bpg(?:slot|soft)?\b", re.I),
    "gacor": re.compile(r"gacor", re.I),
    "togel": re.compile(r"togel", re.I),
    "th_slot": re.compile("\u0E2A\u0E25\u0E47\u0E2D\u0E15"),            # Thai "slot"
    "th_baccarat": re.compile("\u0E1A\u0E32\u0E04\u0E32\u0E23\u0E48\u0E32"),  # Thai "baccarat"
}
# Adult terms: compiled from code points so the words never appear as plain
# text; results are reported ONLY as booleans under neutral column names.
ADULT_LATIN = [re.compile(r"\bporn", re.I), re.compile(r"\bxxx\b", re.I)]
ADULT_ARABIC = [
    re.compile("\u0633\u0643\u0633"),
    re.compile("\u0646\u064A\u0643"),
]

CSV_FIELDS = [
    "kind", "url", "variant", "variant_label", "error", "status", "location",
    "location_offsite", "size", "sha256", "title", "thai_chars", "cjk_chars",
    "gambling_any", "gambling_terms", "adult_latin", "adult_arabic", "elapsed_ms",
]


def is_pua_host(url):
    host = (urlparse(url).hostname or "").lower()
    return host == "pua.edu.eg" or host.endswith(".pua.edu.eg")


def safe_title(body_text):
    """Return the <title>; if it contains adult terms, redact it entirely."""
    m = TITLE_RE.search(body_text)
    if not m:
        return ""
    title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200]
    if any(p.search(title) for p in ADULT_LATIN + ADULT_ARABIC):
        return "[REDACTED: adult terms in title]"
    return title


def analyse(body_bytes, encoding):
    try:
        text = body_bytes.decode(encoding or "utf-8", errors="replace")
    except LookupError:
        text = body_bytes.decode("utf-8", errors="replace")
    gambling_hits = [name for name, rx in GAMBLING_TERMS.items() if rx.search(text)]
    return {
        "size": len(body_bytes),
        "sha256": hashlib.sha256(body_bytes).hexdigest(),
        "title": safe_title(text),
        "thai_chars": len(THAI_RE.findall(text)),
        "cjk_chars": len(CJK_RE.findall(text)),
        "gambling_any": bool(gambling_hits),
        "gambling_terms": "|".join(gambling_hits),
        "adult_latin": any(p.search(text) for p in ADULT_LATIN),
        "adult_arabic": any(p.search(text) for p in ADULT_ARABIC),
    }


def fetch(session, url, variant_key):
    row = {f: "" for f in CSV_FIELDS}
    row.update({"url": url, "variant": variant_key, "variant_label": VARIANTS[variant_key]["label"]})
    if not is_pua_host(url):
        row["error"] = "refused: not a pua.edu.eg host"
        return row
    t0 = time.monotonic()
    try:
        resp = session.get(
            url,
            headers=VARIANTS[variant_key]["headers"],
            allow_redirects=False,
            timeout=TIMEOUT,
            stream=True,
        )
        body = resp.raw.read(MAX_BODY, decode_content=True) or b""
        resp.close()
        row["status"] = resp.status_code
        loc = resp.headers.get("Location", "")
        row["location"] = loc[:300]
        if loc:
            absolute = loc if "://" in loc else url  # relative = same host
            row["location_offsite"] = not is_pua_host(absolute)
        else:
            row["location_offsite"] = False
        ctype = resp.headers.get("Content-Type", "")
        enc = resp.encoding if "charset" in ctype.lower() else "utf-8"
        row.update(analyse(body, enc))
    except requests.RequestException as exc:
        row["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    row["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
    return row


def spam_signals(r):
    return bool(r.get("gambling_any") is True or r.get("adult_latin") is True
                or r.get("adult_arabic") is True
                or (isinstance(r.get("thai_chars"), int) and r["thai_chars"] > 0)
                or (isinstance(r.get("cjk_chars"), int) and r["cjk_chars"] > 20))


def compare(base, other):
    """Return list of human-readable differences of `other` vs baseline `base`."""
    diffs = []
    if base.get("error") or other.get("error"):
        if bool(base.get("error")) != bool(other.get("error")):
            diffs.append("one request errored, the other did not")
        return diffs
    if base["status"] != other["status"]:
        diffs.append(f"status {base['status']} -> {other['status']}")
    if other["location"] and other["location"] != base["location"]:
        diffs.append("redirect" + (" OFF-SITE" if other["location_offsite"] else "")
                     + f" to {other['location'][:120]}")
    if base["title"] != other["title"]:
        diffs.append(f"title differs: '{base['title'][:60]}' -> '{other['title'][:60]}'")
    bs, os_ = base["size"], other["size"]
    if max(bs, os_) > 0 and abs(bs - os_) / max(bs, 1) > 0.10:
        diffs.append(f"size {bs} -> {os_} bytes ({(os_ - bs) / max(bs, 1):+.0%})")
    new_spam = []
    for k in ("thai_chars", "cjk_chars"):
        if other[k] > base[k] + 5:
            new_spam.append(f"{k} {base[k]}->{other[k]}")
    if other["gambling_any"] and not base["gambling_any"]:
        new_spam.append(f"gambling terms ({other['gambling_terms']})")
    if other["adult_latin"] and not base["adult_latin"]:
        new_spam.append("adult terms (Latin)")
    if other["adult_arabic"] and not base["adult_arabic"]:
        new_spam.append("adult terms (Arabic)")
    if new_spam:
        diffs.append("SPAM SIGNALS: " + ", ".join(new_spam))
    return diffs


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_markdown(path, rows, started):
    by_url = {}
    for r in rows:
        by_url.setdefault((r["kind"], r["url"]), {})[r["variant"]] = r

    lines = [
        "# Cloak check - *.pua.edu.eg",
        "",
        f"Run started: {started} UTC. Variants: "
        + "; ".join(f"**{k}** = {v['label']}" for k, v in VARIANTS.items()) + ".",
        "",
        "> **Caveat:** many IIS cloaking modules (BADIIS / GhostRedirector-Gamshen) verify "
        "Googlebot by **IP address** (reverse DNS / Google IP ranges). These requests come from a "
        "non-Google IP, so **\"no difference\" here does NOT mean the site is clean.** The "
        "authoritative test is Search Console > URL Inspection > Test live URL > View crawled page.",
        "",
    ]

    errors = [r for r in rows if r["error"]]
    if errors and len(errors) == len(rows):
        lines += [
            "## Run status: NO DATA",
            "",
            "Every request failed, so nothing was compared. First error: "
            f"`{md_escape(errors[0]['error'])}`. Re-run this script from a network that can reach "
            "*.pua.edu.eg (e.g. an office or home connection).",
            "",
        ]

    flagged = []
    for (kind, url), vs in by_url.items():
        base = vs.get("A")
        for k in "BCDE":
            if base and k in vs:
                d = compare(base, vs[k])
                if d:
                    flagged.append((kind, url, k, d))
        # spam present in the baseline itself is worth flagging too
        if base and not base["error"] and spam_signals(base):
            flagged.append((kind, url, "A", ["spam signals present even for normal browser"]))

    lines += ["## Flags", ""]
    if flagged:
        for kind, url, k, d in flagged:
            lines.append(f"- **{url}** ({kind}) - variant **{k}**: " + "; ".join(md_escape(x) for x in d))
    elif errors and len(errors) == len(rows):
        lines.append("- None (no data - see run status above).")
    else:
        lines.append("- No variant differed from the normal-browser baseline. See caveat above: "
                     "this does NOT prove the site is clean.")
    lines += ["", "## Per-URL detail", ""]

    for (kind, url), vs in by_url.items():
        lines += [f"### {url} ({kind})", "",
                  "| Var | Status | Location | Size | SHA-256 (12) | Title | Thai | CJK | Gambling | Adult-Lat | Adult-Ar | Error |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for k in "ABCDE":
            r = vs.get(k)
            if not r:
                continue
            lines.append("| " + " | ".join(md_escape(x) for x in [
                k, r["status"], r["location"][:60], r["size"], str(r["sha256"])[:12],
                str(r["title"])[:50], r["thai_chars"], r["cjk_chars"],
                r["gambling_terms"] or r["gambling_any"], r["adult_latin"], r["adult_arabic"],
                r["error"][:60],
            ]) + " |")
        lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return flagged


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    started = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    session = requests.Session()
    rows = []
    first = True
    for kind, url in URLS:
        for k in VARIANTS:
            if not first:
                time.sleep(DELAY_SECONDS)
            first = False
            r = fetch(session, url, k)
            r["kind"] = kind
            rows.append(r)
            print(f"[{k}] {r['status'] or 'ERR':>3} {r['size'] or '-':>7} "
                  f"thai={r['thai_chars'] or 0} gamb={r['gambling_any'] or False} "
                  f"adult={bool(r['adult_latin'] is True or r['adult_arabic'] is True)} {url}"
                  + (f"  ({r['error'][:80]})" if r["error"] else ""), flush=True)

    csv_path = os.path.join(args.out, "cloak_check.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    md_path = os.path.join(args.out, "cloak_check.md")
    flagged = write_markdown(md_path, rows, started)
    print(f"\nWrote {csv_path} and {md_path}; {len(flagged)} flag(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
