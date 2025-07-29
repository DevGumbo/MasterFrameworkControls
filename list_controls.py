#!/usr/bin/env python3
"""
List available controls
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from framework.control_loader import ControlLoader

loader = ControlLoader('./control_definitions')
controls = loader.load_controls()

print(f"Available controls ({len(controls)} total):\n")

for control_id, control in sorted(controls.items()):
    print(f"{control_id}: {control['title']}")
    print(f"  Service: {control.get('service', 'unknown')}")
    print(f"  Severity: {control['severity']}")
    print(f"  Standards: {', '.join(control.get('standards', {}).keys())}")
    print()
