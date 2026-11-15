"""Bounded sequential preview benchmark; synthetic PDFs never touch real storage/DB."""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ['DEBUG']='false'
from tests.phase2.conftest import make_pdf
results=[]
with tempfile.TemporaryDirectory(prefix='p4-preview-',dir='data/tmp') as root:
    for mb in [1,5,10,20]:
        path=Path(root)/'fixture.pdf'
        path.write_bytes(make_pdf(target_size=mb*1024*1024))
        result=subprocess.run(['node','--expose-gc','scripts/benchmark_pdf_preview.cjs',str(path)],capture_output=True,text=True,timeout=45)
        if result.returncode: raise RuntimeError(result.stderr)
        item=json.loads(result.stdout.strip().splitlines()[-1]);item['target_mb']=mb;results.append(item)
report={'timestamp':datetime.now(timezone.utc).isoformat(),'results':results,'limitations':'Synthetic blank content; not scanned/complex/malicious PDFs, browser E2E or repeated browser heap leak proof. No claim of PDF Worker sandboxing.'}
Path('docs/phase4-pdf-memory.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
