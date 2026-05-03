from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent

IDA_DIR = PROJECT_ROOT / 'IDA'
SIMULATE_DIR = PROJECT_ROOT / 'Simulate'
X64DBG_DIR = PROJECT_ROOT / 'X64Dbg'

print('PROJECT_ROOT:', PROJECT_ROOT)

for path in (PROJECT_ROOT, IDA_DIR, SIMULATE_DIR, X64DBG_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
