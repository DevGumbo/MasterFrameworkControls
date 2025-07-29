#!/usr/bin/env python3
"""
Smart Control Processor
Analyzes controls and generates complete control definitions with interrogator mappings
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Any
import re

class SmartControlProcessor:
    """Processes controls with pattern analysis"""
    
    def __init__(self):
        # Existing interrogators and what they can check
        self.existing_interrogators = {
            'NetworkSecurityInterrogator': {
                'patterns': ['0.0.0.0/0', 'security group', 'nacl', 'network acl'],
                'capabilities': ['ingress_rules', 'egress_rules', 'default_sg_rules']
            },
            'ResourcePublicAccessInterrogator': {
                'patterns': ['public', 'publicly accessible', 'public access'],
                'capabilities': ['S3Bucket', 'EBSSnapshot', 'RDSInstance']
            },
            'EncryptionConfigInterrogator': {
                'patterns': ['encrypt', 'encryption', 'tls', 'https', 'kms'],
                'capabilities': ['at_rest', 'in_transit', 'tls_version']
            },
            'IAMPolicyInterrogator': {
                'patterns': ['password', 'mfa', 'access key', 'credential'],
                'capabilities': ['password_policy', 'mfa_check', 'key_rotation']
            },
            'LoggingConfigInterrogator': {
                'patterns': ['log', 'trail', 'flow log', 'audit'],
                'capabilities': ['cloudtrail', 'vpc_flow_logs', 's3_logging']
            }
        }
        
    def analyze_control(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a control and determine interrogation strategy"""
        title = control['Title'].lower()
        description = control['Description'].lower()
        control_id = control['ControlId']
        
        # Find matching interrogator
        matched_interrogator = None
        matched_pattern = None
        
        for interrogator, config in self.existing_interrogators.items():
            for pattern in config['patterns']:
                if pattern in title or pattern in description:
                    matched_interrogator = interrogator
                    matched_pattern = pattern
                    break
            if matched_interrogator:
                break
                
        # Extract specific parameters
        parameters = self.extract_parameters(control, matched_interrogator, matched_pattern)
        
        return {
            'interrogator': matched_interrogator,
            'pattern': matched_pattern,
            'parameters': parameters,
            'needs_new': matched_interrogator is None
        }
        
    def extract_parameters(self, control: Dict[str, Any], interrogator: str, pattern: str) -> Dict[str, Any]:
        """Extract control-specific parameters"""
        params = {}
        title = control['Title'].lower()
        description = control['Description'].lower()
        
        if interrogator == 'NetworkSecurityInterrogator':
            # Extract ports from description
            port_numbers = re.findall(r'\b\d{2,5}\b', control['Description'])
            params = {
                'check_type': 'ingress_rules',
                'ports': [int(p) for p in port_numbers] if port_numbers else [22, 3389],
                'source_cidr': '0.0.0.0/0'
            }
            
        elif interrogator == 'ResourcePublicAccessInterrogator':
            # Determine resource type
            if 'ebs' in title or 'snapshot' in title:
                params = {'resource_type': 'EBSSnapshot', 'check_type': 'public_sharing'}
            elif 'rds' in title:
                params = {'resource_type': 'RDSInstance', 'check_type': 'publicly_accessible'}
            elif 's3' in title:
                params = {'resource_type': 'S3Bucket', 'check_type': 'block_public_access'}
                
        elif interrogator == 'EncryptionConfigInterrogator':
            # Determine encryption type
            if 'at rest' in title or 'at-rest' in title:
                params = {'encryption_type': 'at_rest'}
            elif 'in transit' in title or 'https' in title:
                params = {'encryption_type': 'in_transit'}
            if 'tls' in title:
                tls_version = re.search(r'tls\s*(\d+\.?\d*)', title)
                if tls_version:
                    params['min_tls_version'] = tls_version.group(1)
                    
        return params
        
    def generate_control_definition(self, control: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate complete control definition"""
        control_def = {
            'control_id': control['ControlId'].replace('.', '_'),
            'title': control['Title'],
            'description': control['Description'],
            'severity': control['SeverityRating'],
            'interrogation': {
                'class': analysis['interrogator'] or 'UnknownInterrogator',
                'method': 'execute',
                'parameters': analysis['parameters']
            },
            'standards': {
                'control_tower': {
                    'control_id': control['ControlId'],
                    'severity': control['SeverityRating']
                }
            }
        }
        
        return control_def
        
    def process_csv_file(self, csv_file: str, output_dir: str):
        """Process CSV file and generate control definitions"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        controls_by_service = {}
        needs_new_interrogators = []
        
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Analyze control
                analysis = self.analyze_control(row)
                
                # Generate control definition
                control_def = self.generate_control_definition(row, analysis)
                
                # Determine service
                service = self.get_service_from_control_id(row['ControlId'])
                
                if service not in controls_by_service:
                    controls_by_service[service] = []
                    
                controls_by_service[service].append(control_def)
                
                # Track what needs new interrogators
                if analysis['needs_new']:
                    needs_new_interrogators.append({
                        'control_id': row['ControlId'],
                        'title': row['Title'],
                        'suggested_interrogator': self.suggest_interrogator_name(row)
                    })
                    
                # Print analysis
                print(f"\nControl: {row['ControlId']}")
                print(f"  Mapped to: {analysis['interrogator'] or 'NEEDS NEW INTERROGATOR'}")
                if analysis['parameters']:
                    print(f"  Parameters: {json.dumps(analysis['parameters'], indent=4)}")
                    
        # Save control definitions
        for service, controls in controls_by_service.items():
            output_file = output_path / f"controltower_{service}_controls.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'service': service,
                    'controls': controls
                }, f, indent=2)
            print(f"\nSaved {len(controls)} controls to {output_file}")
            
        # Report on new interrogators needed
        if needs_new_interrogators:
            print("\n" + "="*60)
            print("INTERROGATORS NEEDED:")
            for item in needs_new_interrogators:
                print(f"\n{item['control_id']}: {item['title']}")
                print(f"  Suggested class: {item['suggested_interrogator']}")
                
    def get_service_from_control_id(self, control_id: str) -> str:
        """Extract service from control ID"""
        # CT.EC2.PR.4 -> ec2
        parts = control_id.split('.')
        if len(parts) >= 2:
            return parts[1].lower()
        return 'other'
        
    def suggest_interrogator_name(self, control: Dict[str, Any]) -> str:
        """Suggest interrogator name for new controls"""
        title = control['Title'].lower()
        
        if 'kms' in title:
            return 'KMSPolicyInterrogator'
        elif 'lambda' in title:
            return 'LambdaSecurityInterrogator'
        elif 'sqs' in title:
            return 'SQSPolicyInterrogator'
        elif 'region' in title:
            return 'RegionRestrictionInterrogator'
        else:
            service = self.get_service_from_control_id(control['ControlId'])
            return f"{service.upper()}ConfigInterrogator"


if __name__ == "__main__":
    processor = SmartControlProcessor()
    
    # Process Control Tower controls
    processor.process_csv_file(
        '/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/importers/control_tower_controls.csv',
        '/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/control_definitions/aws'
    )
