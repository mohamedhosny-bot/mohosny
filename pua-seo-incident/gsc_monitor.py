#!/usr/bin/env python3
"""
gsc_monitor.py - weekly Search Console spam monitor for pua.edu.eg

Reads a Google Search Console "Performance" export (.xlsx with sheets
Queries, Pages, Countries, Chart - English or Arabic UI) and prints:
  * totals (clicks / impressions) and date range
  * clicks / impressions per host (academic., portal., www., ...)
  * query buckets: Thai / CJK / Arabic-adult / Latin-adult / Latin-gambling / other
    (COUNTS ONLY - query text is never printed)
  * top countries
  * comparison against results/baseline.json (per-day averages)

After the server is cleaned, spam clicks should trend to zero week by week.

Usage:
    python3 gsc_monitor.py export.xlsx [--baseline results/baseline.json] [--json out.json]

Notes:
  * GSC exports contain at most 1,000 rows per sheet and exclude anonymised
    queries, so bucket totals are a lower bound; compare like with like.
  * No query text is ever printed. Page URLs containing adult terms are redacted.
"""

import argparse
import json
import os
import re
import sys
from datetime import date, datetime
from urllib.parse import urlparse

try:
    import openpyxl
except ImportError:
    sys.exit("openpyxl is required: pip install openpyxl")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASELINE = os.path.join(HERE, "results", "baseline.json")

SHEET_ALIASES = {
    "queries": ["queries", "طلبات البحث"],
    "pages": ["pages", "الصفحات"],
    "countries": ["countries", "البلدان"],
    "chart": ["chart", "الرسم البياني"],
}
CLICK_HEADERS = ["clicks", "النقرات"]
IMPR_HEADERS = ["impressions", "مرات الظهور"]

THAI_RE = re.compile(r"[฀-๿]")
CJK_RE = re.compile(r"[぀-ヿ㐀-䶿一-鿿가-힯]")
# Adult terms built from code points; matches are only ever counted.
ARABIC_ADULT_RE = re.compile("|".join([
    "سكس",
    "نيك",
    "منيوك",
    "اباحي",
    "شرموط",
    "مصارة",
]))
LATIN_ADULT_RE = re.compile(r"\b(porn\w*|xxx|sex|xnxx|xvideos?|nude|hentai)\b", re.I)
LATIN_GAMBLING_RE = re.compile(
    r"(slot|casino|gacor|togel|\bpg\b|pgslot|baccarat|judi|\bbet\b|betting|sbobet|joker|"
    r"jackpot|maxwin|ufabet|lottery|poker|roulette|scatter)", re.I)

BUCKETS = ["arabic_adult", "latin_adult", "thai", "cjk", "latin_gambling", "other"]
SPAM_BUCKETS = ["arabic_adult", "latin_adult", "thai", "cjk", "latin_gambling"]


def classify(q):
    q = str(q or "")
    if ARABIC_ADULT_RE.search(q):
        return "arabic_adult"
    if LATIN_ADULT_RE.search(q):
        return "latin_adult"
    if THAI_RE.search(q):
        return "thai"
    if CJK_RE.search(q):
        return "cjk"
    if LATIN_GAMBLING_RE.search(q):
        return "latin_gambling"
    return "other"


def find_sheet(wb, key):
    names = {n.strip().lower(): n for n in wb.sheetnames}
    for alias in SHEET_ALIASES[key]:
        if alias.lower() in names:
            return wb[names[alias.lower()]]
    return None


def read_rows(ws):
    """Return list of (dimension_value, clicks, impressions) from a GSC sheet."""
    if ws is None:
        return []
    it = ws.iter_rows(values_only=True)
    header = next(it, None)
    if not header:
        return []
    h = [str(x or "").strip().lower() for x in header]

    def col(cands):
        for i, name in enumerate(h):
            if name in cands:
                return i
        return None

    ci, ii = col(CLICK_HEADERS), col(IMPR_HEADERS)
    if ci is None or ii is None:
        raise ValueError(f"sheet '{ws.title}': cannot find Clicks/Impressions columns in {h}")
    out = []
    for r in it:
        if r is None or r[0] is None:
            continue
        out.append((r[0], num(r[ci]), num(r[ii])))
    return out


def num(v):
    try:
        return int(float(str(v).replace(",", "")))
    except (TypeError, ValueError):
        return 0


def to_date(v):
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def safe_url(u):
    s = str(u)
    if ARABIC_ADULT_RE.search(s) or LATIN_ADULT_RE.search(s):
        host = urlparse(s).hostname or "?"
        return f"[redacted URL on {host}]"
    return s[:110]


def analyse(path):
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    res = {"file": os.path.basename(path)}

    chart = read_rows(find_sheet(wb, "chart"))
    dates = [d for d in (to_date(r[0]) for r in chart) if d]
    res["date_from"] = min(dates).isoformat() if dates else None
    res["date_to"] = max(dates).isoformat() if dates else None
    res["days"] = (max(dates) - min(dates)).days + 1 if dates else None
    res["chart_clicks"] = sum(r[1] for r in chart)
    res["chart_impressions"] = sum(r[2] for r in chart)
    # weekly trend from the Chart sheet
    weekly = {}
    for r in chart:
        d = to_date(r[0])
        if d:
            wk = f"{d.isocalendar()[0]}-W{d.isocalendar()[1]:02d}"
            c, i = weekly.get(wk, (0, 0))
            weekly[wk] = (c + r[1], i + r[2])
    res["weekly"] = [{"week": k, "clicks": v[0], "impressions": v[1]} for k, v in sorted(weekly.items())]

    queries = read_rows(find_sheet(wb, "queries"))
    b = {k: {"queries": 0, "clicks": 0, "impressions": 0} for k in BUCKETS}
    for q, c, i in queries:
        k = classify(q)
        b[k]["queries"] += 1
        b[k]["clicks"] += c
        b[k]["impressions"] += i
    res["buckets"] = b
    res["spam_clicks"] = sum(b[k]["clicks"] for k in SPAM_BUCKETS)
    res["spam_impressions"] = sum(b[k]["impressions"] for k in SPAM_BUCKETS)
    res["query_rows"] = len(queries)

    pages = read_rows(find_sheet(wb, "pages"))
    hosts = {}
    for u, c, i in pages:
        h = (urlparse(str(u)).hostname or "?").lower()
        hc, hi, hn = hosts.get(h, (0, 0, 0))
        hosts[h] = (hc + c, hi + i, hn + 1)
    res["hosts"] = {h: {"clicks": v[0], "impressions": v[1], "pages": v[2]}
                    for h, v in sorted(hosts.items(), key=lambda kv: -kv[1][0])}
    res["top_pages"] = [{"url": safe_url(u), "clicks": c, "impressions": i}
                        for u, c, i in sorted(pages, key=lambda r: -r[1])[:10]]

    countries = read_rows(find_sheet(wb, "countries"))
    res["top_countries"] = [{"country": str(n), "clicks": c, "impressions": i}
                            for n, c, i in sorted(countries, key=lambda r: -r[1])[:10]]
    th = [r for r in countries if str(r[0]).strip().lower() in ("thailand", "تايلاند")]
    res["thailand_clicks"] = th[0][1] if th else 0
    return res


def per_day(v, days):
    return (v / days) if (days and v is not None) else None


def fmt(n):
    return f"{n:,.0f}" if isinstance(n, (int, float)) else "n/a"


def compare(res, base):
    days = res["days"]
    bdays = base["period"]["days"]
    rows = []

    def add(label, cur, bval):
        cd, bd = per_day(cur, days), per_day(bval, bdays)
        change = f"{(cd - bd) / bd:+.0%}" if (cd is not None and bd) else "n/a"
        rows.append((label, fmt(cur), f"{cd:,.1f}" if cd is not None else "n/a",
                     fmt(bval), f"{bd:,.1f}" if bd is not None else "n/a", change))

    b = res["buckets"]
    add("Spam clicks (all buckets)", res["spam_clicks"], base["spam"]["clicks"])
    add("Spam impressions", res["spam_impressions"], base["spam"]["impressions"])
    add("Thai gambling clicks", b["thai"]["clicks"], base["spam"]["thai_gambling_clicks"])
    add("Arabic adult clicks", b["arabic_adult"]["clicks"], base["spam"]["arabic_adult_clicks"])
    add("Thailand country clicks", res["thailand_clicks"], base.get("thailand_clicks"))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("xlsx")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE)
    ap.add_argument("--json", help="also write the parsed numbers to this JSON file")
    args = ap.parse_args()

    res = analyse(args.xlsx)
    print(f"GSC export: {res['file']}")
    print(f"Period: {res['date_from']} .. {res['date_to']} ({res['days']} days)")
    print(f"Totals (Chart sheet): clicks {fmt(res['chart_clicks'])}, impressions {fmt(res['chart_impressions'])}")

    print("\nPer host (Pages sheet, top 1,000 pages):")
    for h, v in res["hosts"].items():
        print(f"  {h:<28} clicks {fmt(v['clicks']):>9}  impressions {fmt(v['impressions']):>11}  pages {v['pages']}")

    print(f"\nQuery buckets ({res['query_rows']} query rows; query text intentionally not shown):")
    for k in BUCKETS:
        v = res["buckets"][k]
        print(f"  {k:<15} queries {v['queries']:>5}  clicks {fmt(v['clicks']):>9}  impressions {fmt(v['impressions']):>11}")
    print(f"  {'SPAM TOTAL':<15} {'':>13}  clicks {fmt(res['spam_clicks']):>9}  impressions {fmt(res['spam_impressions']):>11}")

    print("\nTop countries by clicks:")
    for c in res["top_countries"]:
        print(f"  {c['country']:<24} clicks {fmt(c['clicks']):>9}  impressions {fmt(c['impressions']):>11}")

    print("\nTop pages by clicks:")
    for p in res["top_pages"]:
        print(f"  {fmt(p['clicks']):>7}  {p['url']}")

    if res["weekly"]:
        print("\nWeekly trend (all queries):")
        for w in res["weekly"][-8:]:
            print(f"  {w['week']}  clicks {fmt(w['clicks']):>8}  impressions {fmt(w['impressions']):>10}")

    if os.path.exists(args.baseline):
        with open(args.baseline, encoding="utf-8") as fh:
            base = json.load(fh)
        print(f"\nVs baseline ({base['period']['label']}, {base['period']['days']} days) - per-day averages:")
        print(f"  {'metric':<28} {'now':>9} {'now/day':>9} {'base':>9} {'base/day':>9} {'change':>7}")
        for r in compare(res, base):
            print(f"  {r[0]:<28} {r[1]:>9} {r[2]:>9} {r[3]:>9} {r[4]:>9} {r[5]:>7}")
        spd = per_day(res["spam_clicks"], res["days"]) or 0
        verdict = ("CLEAN: no spam clicks in this export" if res["spam_clicks"] == 0
                   else "IMPROVING" if spd < 0.5 * per_day(base["spam"]["clicks"], base["period"]["days"])
                   else "STILL COMPROMISED / NOT YET DROPPING")
        print(f"\nVerdict: {verdict}")
    else:
        print(f"\n(no baseline found at {args.baseline})")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
        print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()
