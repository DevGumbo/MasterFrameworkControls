#!/usr/bin/env python3
"""
Dry run analysis - shows what would be checked without AWS calls
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from framework.control_loader import ControlLoader
from collections import defaultdict

def analyze_controls():
    """Analyze control coverage"""
    loader = ControlLoader('./control_definitions')
    controls = loader.load_controls()
    
    # Group by interrogator
    by_interrogator = defaultdict(list)
    by_service = defaultdict(list)
    
    for control_id, control in controls.items():
        interrogator = control['interrogation']['class']
        service = control.get('service', 'unknown')
        
        by_interrogator[interrogator].append(control_id)
        by_service[service].append(control_id)
    
    print(f"Total controls: {len(controls)}\n")
    
    print("Controls by Interrogator:")
    print("="*60)
    for interrogator, control_ids in sorted(by_interrogator.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{interrogator}: {len(control_ids)} controls")
    
    print("\nControls by Service:")
    print("="*60)
    for service, control_ids in sorted(by_service.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{service}: {len(control_ids)} controls")
    
    # Find working interrogators
    from framework.interrogator_registry import InterrogatorRegistry
    registry = InterrogatorRegistry()
    available = registry.discover('./interrogators')
    
    print("\nAvailable Interrogators:")
    print("="*60)
    for name in available:
        print(f"✓ {name}")
    
    print("\nCoverage Analysis:")
    print("="*60)
    working_controls = 0
    for control_id, control in controls.items():
        if control['interrogation']['class'] in available:
            working_controls += 1
    
    print(f"Working controls: {working_controls}/{len(controls)} ({working_controls/len(controls)*100:.1f}%)")
    
    # Show what's missing
    missing = set(by_interrogator.keys()) - set(available.keys())
    if missing:
        print("\nMissing Interrogators:")
        for m in sorted(missing):
            print(f"✗ {m} ({len(by_interrogator[m])} controls)")

if __name__ == '__main__':
    analyze_controls()
