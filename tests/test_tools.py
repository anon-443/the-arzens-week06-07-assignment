import csv, json, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).parents[1]
def test_enricher_offline():
    out = Path(tempfile.mktemp(suffix='.json'))
    subprocess.run([sys.executable, str(ROOT/'task-2-ti-enrichment/ti_enricher.py'), '--indicator', '8.8.8.8', '--format', 'json', '--output', str(out), '--offline'], check=True)
    data = json.loads(out.read_text()); assert data[0]['risk_score'] == 0; assert data[0]['type'] == 'ipv4'
def test_ioc_manager_import_and_export():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d)/'db.json'; bl = Path(d)/'block.txt'
        subprocess.run([sys.executable, str(ROOT/'task-3-ioc-manager/ioc_manager.py'), '--add-file', str(ROOT/'task-3-ioc-manager/sample_indicators.csv'), '--db', str(db), '--export-blocklist', '--output', str(bl)], check=True)
        data = json.loads(db.read_text()); assert '8.8.8.8|ipv4' in data; assert bl.exists()
