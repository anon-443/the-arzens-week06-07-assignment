#!/usr/bin/env python3
"""JSON IOC lifecycle manager with expiry, confidence, blocklist, and report outputs."""
from __future__ import annotations
import argparse, csv, json
from datetime import datetime, timedelta, timezone
from pathlib import Path

def now(): return datetime.now(timezone.utc)
def parse(s): return datetime.fromisoformat(s.replace('Z', '+00:00'))
def load(path):
    try: return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError): return {}
def save(path, data): Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
def confidence(record):
    diversity = min(1.0, len(set(record.get('sources', []))) / 3)
    score_stability = 1.0 if len(record.get('observations', [])) < 2 else max(0.0, 1.0 - (max(x.get('risk_score', 0) for x in record['observations']) - min(x.get('risk_score', 0) for x in record['observations'])) / 100)
    age_days = max(0, (now() - parse(record['last_seen'])).days)
    recency = max(0.0, 1 - age_days / 90)
    return round(0.45 * diversity + 0.30 * score_stability + 0.25 * recency, 2)
def add_file(db, path, offline=False):
    with open(path, newline='') as f:
        for row in csv.DictReader(f):
            indicator, typ = row['indicator'].strip(), row.get('type', 'unknown').strip()
            key = f'{indicator}|{typ}'; t = now().isoformat()
            rec = db.setdefault(key, {'indicator': indicator, 'type': typ, 'first_seen': t, 'last_seen': t, 'expiration': (now()+timedelta(days=30)).isoformat(), 'risk_score': 0, 'confidence': 0.0, 'sources': [], 'status': 'active', 'observations': []})
            rec['last_seen'] = t; rec['status'] = 'active'; rec['confidence'] = confidence(rec)
def expire(db):
    changed = 0
    for rec in db.values():
        if rec.get('status') == 'active' and parse(rec['expiration']) <= now(): rec['status'] = 'expired'; changed += 1
    return changed
def export_blocklist(db, path, min_score=80, min_conf=0.65):
    lines = ['# Generated SIEM blocklist; review before production use']
    for rec in db.values():
        if rec.get('status') == 'active' and rec.get('risk_score', 0) >= min_score and rec.get('confidence', 0) >= min_conf: lines.append(f"{rec['indicator']} # score={rec['risk_score']} confidence={rec['confidence']}")
    Path(path).write_text('\n'.join(lines) + '\n')
def report(db, path):
    active = [x for x in db.values() if x.get('status') == 'active']; expired = [x for x in db.values() if x.get('status') == 'expired']
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>IOC Weekly Report</title><style>body{{font-family:Arial;max-width:900px;margin:2rem auto}}td,th{{border:1px solid #ccc;padding:.5rem}}table{{border-collapse:collapse;width:100%}}</style></head><body><h1>IOC Weekly Report</h1><p>Generated {now().isoformat()}</p><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Active IOCs</td><td>{len(active)}</td></tr><tr><td>Expired IOCs</td><td>{len(expired)}</td></tr><tr><td>High-risk IOCs</td><td>{sum(x.get('risk_score',0)>=80 for x in active)}</td></tr></table></body></html>"""
    Path(path).write_text(html)
def main():
    p=argparse.ArgumentParser(); p.add_argument('--db', default=str(Path(__file__).with_name('ioc_database.json'))); p.add_argument('--add-file'); p.add_argument('--update-all', action='store_true'); p.add_argument('--expire-check', action='store_true'); p.add_argument('--export-blocklist', action='store_true'); p.add_argument('--output', default='blocklist.txt'); p.add_argument('--report', default='weekly_report.html'); p.add_argument('--offline', action='store_true'); args=p.parse_args()
    db=load(args.db)
    if args.add_file: add_file(db, args.add_file, args.offline)
    if args.update_all:
        for rec in db.values(): rec['last_seen'] = now().isoformat(); rec['confidence'] = confidence(rec)
    if args.expire_check: print(f'expired={expire(db)}')
    if args.export_blocklist: export_blocklist(db, args.output)
    save(args.db, db); report(db, args.report)
if __name__ == '__main__': main()
