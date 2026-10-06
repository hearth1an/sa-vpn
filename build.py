#!/usr/bin/env python3
"""Build self-contained deployment tools; --check rejects any stale output."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
routing = (root / 'routing.py').read_text().rstrip()
marker = '# @@ROUTING@@'


def standalone(source):
    if source.count(marker) != 1:
        raise ValueError('Expected exactly one routing marker')
    position = source.index(marker)
    start = source.rfind('\n', 0, position) + 1
    end = source.index('\n', position)
    # Replace the marked import, not arbitrary identifiers in the source.
    return source[:start] + routing + source[end:]


manager = standalone((root / 'manager.py').read_text()).rstrip()
template = (root / 'install.template.sh').read_text()
assert template.count('@@MANAGER@@') == 1
outputs = {
    root / 'install.sh': template.replace('@@MANAGER@@', manager),
    root / 'tools/apply_happ_routing_3xui.py': standalone(
        (root / 'tools/apply_happ_routing_3xui.template.py').read_text()),
}
if sys.argv[1:] == ['--manager']:
    print(manager)
elif sys.argv[1:] in ([], ['--check']):
    for target, result in outputs.items():
        if '--check' in sys.argv:
            if not target.exists() or target.read_text() != result:
                sys.exit(f'{target.relative_to(root)} is stale: run python3 build.py')
        else:
            target.write_text(result)
            target.chmod(0o755)
else:
    sys.exit('Usage: python3 build.py [--check|--manager]')
