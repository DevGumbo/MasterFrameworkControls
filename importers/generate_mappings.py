#!/usr/bin/env python3
"""
Standards Mapping Generator
Generates complete standards mappings from control definitions
"""

import json
from pathlib import Path
from collections import defaultdict

def generate_standards_mappings():
    """Generate standards mapping files from control definitions"""
    
    # Load all control definitions
    control_dir = Path('./control_definitions/aws')
    standards_mappings = defaultdict(dict)
    
    # Read all control JSON files
    for json_file in control_dir.glob('*.json'):
        with open(json_file, 'r') as f:
            data = json.load(f)
            
        # Process each control
        for control in data.get('controls', []):
            control_id = control['control_id']
            
            # Extract standards mappings
            for standard, standard_info in control.get('standards', {}).items():
                original_id = standard_info.get('control_id')
                if original_id:
                    standards_mappings[standard][original_id] = control_id
    
    # Save mapping files
    standards_dir = Path('./control_definitions/standards')
    standards_dir.mkdir(parents=True, exist_ok=True)
    
    for standard, mappings in standards_mappings.items():
        # Sort by key for readability
        sorted_mappings = dict(sorted(mappings.items()))
        
        # Save to file
        output_file = standards_dir / f"{standard}_mapping.json"
        with open(output_file, 'w') as f:
            json.dump(sorted_mappings, f, indent=2)
            
        print(f"Generated {output_file.name} with {len(mappings)} mappings")
    
    # Also generate a reverse mapping (internal ID → all standards)
    reverse_mapping = defaultdict(dict)
    
    for standard, mappings in standards_mappings.items():
        for original_id, internal_id in mappings.items():
            reverse_mapping[internal_id][standard] = original_id
    
    # Save reverse mapping
    with open(standards_dir / 'control_to_standards_mapping.json', 'w') as f:
        json.dump(dict(reverse_mapping), f, indent=2)
        
    print(f"\nGenerated reverse mapping with {len(reverse_mapping)} controls")
    
    # Generate summary report
    print("\nStandards Coverage Summary:")
    print("="*50)
    for standard, mappings in sorted(standards_mappings.items()):
        print(f"{standard}: {len(mappings)} controls mapped")


if __name__ == "__main__":
    generate_standards_mappings()
