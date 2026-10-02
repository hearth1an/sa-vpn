#!/usr/bin/env python3
"""Build the one-file installer; --check rejects stale generated output."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
template = (root / 'install.template.sh').read_text()
assert template.count('@@MANAGER@@') == 1
result = template.replace('@@MANAGER@@', (root / 'manager.py').read_text().rstrip())
target = root / 'install.sh'
if '--check' in sys.argv:
    if not target.exists() or target.read_text() != result:
        sys.exit('install.sh is stale: run python3 build.py')
else:
    target.write_text(result)
    target.chmod(0o755)
