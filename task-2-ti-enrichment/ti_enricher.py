#!/usr/bin/env python3
"""Multi-source IOC enrichment with caching, rate limiting, and offline mode."""
from __future__ import annotations
import argparse, csv, hashlib, json, os, re, sys, time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
try:
    import requests
except ImportError:
    requests = None
try:
    import yaml
except ImportError:
    yaml = None

@dataclass
class Result:
    indicator: str
    type: str
    risk_score: int
    confidence: float
    sources: dict[str, Any]
    errors: list[str]
    queried_at: str

class Cache:
    def __init__(self, path: Path, ttl: int):
        self.path, self.ttl = path, ttl
        try: self.data = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError): self.data = {}
    def get(self, key):
        item = self.data.get(key)
        if item and time.time() - item.get('stored_at', 0) < self.ttl: return item['value']
        return None
    def set(self, key, value):
        self.data[key] = {'stored_at': time.time(), 'value': value}
    def save(self):
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True))

class Limiter:
    def __init__(self, min_interval: float): self.min_interval, self.last = min_interval, 0.0
    def wait(self):
        delay = self.min_interval - (time.monotonic() - self.last)
        if delay > 0: time.sleep(delay)
        self.last = time.monotonic()

def kind(value: str) -> str:
    v = value.strip().lower()
    if re.fullmatch(r'[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}', v): return 'hash'
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', v): return 'ipv4'
    if v.startswith(('http://', 'https://')): return 'url'
    return 'domain'

def env_key(name):
    return os.getenv(name) or ''

def safe_get(url, headers, params=None, timeout=12):
    if requests is None: raise RuntimeError('requests is not installed')
    last_error = None
    for attempt in range(3):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            if response.status_code == 429 or response.status_code >= 500:
                last_error = RuntimeError(f'transient provider status {response.status_code}')
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict): raise ValueError('provider returned a non-object JSON response')
            return data
        except Exception as exc:
            last_error = exc
            if attempt < 2: time.sleep(2 ** attempt)
    raise last_error

def score(sources):
    vals = [int(v.get('risk', 0)) for v in sources.values() if isinstance(v, dict) and v.get('available')]
    if not vals: return 0, 0.0
    risk = round(sum(vals) / len(vals))
    diversity = min(1.0, len(vals) / 3)
    agreement = 1 - (max(vals) - min(vals)) / 100
    return max(0, min(100, risk)), round(0.55 * diversity + 0.45 * max(0, agreement), 2)

def enrich(indicator, cache, offline=False, timeout=12):
    indicator, typ = indicator.strip(), kind(indicator)
    sources, errors = {}, []
    limiters = {'virustotal': Limiter(15.0), 'abuseipdb': Limiter(0.1), 'otx': Limiter(0.2)}
    configs = [
        ('virustotal', env_key('VT_API_KEY'), 'https://www.virustotal.com/api/v3/search', {'x-apikey': env_key('VT_API_KEY')}, {'query': indicator}),
        ('abuseipdb', env_key('ABUSEIPDB_API_KEY'), 'https://api.abuseipdb.com/api/v2/check', {'Key': env_key('ABUSEIPDB_API_KEY'), 'Accept': 'application/json'}, {'ipAddress': indicator, 'maxAgeInDays': '90'}),
        ('otx', env_key('OTX_API_KEY'), f'https://otx.alienvault.com/api/v1/indicators/{typ}/{indicator}/general', {'X-OTX-API-KEY': env_key('OTX_API_KEY')} , None),
    ]
    for name, key, url, headers, params in configs:
        ck = hashlib.sha256(f'{name}:{typ}:{indicator}'.encode()).hexdigest()
        cached = cache.get(ck)
        if cached is not None: sources[name] = {**cached, 'cached': True}; continue
        if offline or not key:
            sources[name] = {'available': False, 'risk': 0, 'detail': 'offline mode or API key not configured'}; continue
        try:
            limiters[name].wait()
            data = safe_get(url, headers, params, timeout)
            # Provider-specific extraction is deliberately defensive.
            if name == 'abuseipdb': risk = int(data.get('data', {}).get('abuseConfidenceScore', 0))
            elif name == 'virustotal':
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                total = sum(int(stats.get(k, 0)) for k in ('malicious', 'suspicious', 'harmless', 'undetected'))
                risk = round(100 * (stats.get('malicious', 0) + 0.5 * stats.get('suspicious', 0)) / total) if total else 0
            else: risk = min(100, int(data.get('pulse_info', {}).get('count', 0) * 10))
            value = {'available': True, 'risk': max(0, min(100, risk)), 'detail': 'provider response parsed'}
            cache.set(ck, value); sources[name] = value
        except Exception as exc:
            msg = f'{name}: {type(exc).__name__}: {exc}'
            errors.append(msg); sources[name] = {'available': False, 'risk': 0, 'detail': msg}
    risk, confidence = score(sources)
    return Result(indicator, typ, risk, confidence, sources, errors, datetime.now(timezone.utc).isoformat())

def load_indicators(args):
    if args.indicator: return [args.indicator]
    with open(args.input_file, newline='') as f:
        return [row['indicator'] for row in csv.DictReader(f) if row.get('indicator')]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indicator'); p.add_argument('--input-file'); p.add_argument('--format', choices=['table','json','csv'], default='table')
    p.add_argument('--output'); p.add_argument('--cache', default=str(Path(__file__).with_name('cache.json'))); p.add_argument('--offline', action='store_true')
    args = p.parse_args()
    if not args.indicator and not args.input_file: p.error('provide --indicator or --input-file')
    cache = Cache(Path(args.cache), int(os.getenv('TI_CACHE_TTL', '3600')))
    results = [enrich(i, cache, args.offline) for i in load_indicators(args)]; cache.save()
    rows = [asdict(r) for r in results]
    if args.format == 'json': out = json.dumps(rows, indent=2)
    elif args.format == 'csv':
        import io
        buf = io.StringIO(); w = csv.DictWriter(buf, fieldnames=['indicator','type','risk_score','confidence','sources','errors','queried_at']); w.writeheader()
        for r in rows: w.writerow({**r, 'sources': json.dumps(r['sources']), 'errors': '; '.join(r['errors'])})
        out = buf.getvalue()
    else:
        out = 'INDICATOR                         TYPE    RISK  CONF  ERRORS\n' + '-'*75 + '\n'
        out += '\n'.join(f"{r.indicator[:32]:32} {r.type:7} {r.risk_score:4}  {r.confidence:.2f}  {len(r.errors)}" for r in results)
    if args.output: Path(args.output).write_text(out)
    else: print(out)

if __name__ == '__main__': main()
