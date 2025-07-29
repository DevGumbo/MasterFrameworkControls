#!/usr/bin/env python3
"""
Security Control Grabber
Fetches latest control definitions from various sources
"""

import requests
import json
import csv
from pathlib import Path
from datetime import datetime
import re

class SecurityControlGrabber:
    """Fetches security controls from various sources"""
    
    def __init__(self, output_dir="./control_definitions/raw"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def fetch_aws_config_rules(self):
        """Fetch AWS Config conformance pack rules"""
        # This would normally fetch from AWS Config API or GitHub
        # For now, placeholder
        print("Fetching AWS Config rules...")
        # In reality: boto3.client('config').describe_conformance_packs()
        
    def fetch_prowler_checks(self):
        """Fetch Prowler security checks from GitHub"""
        print("Fetching Prowler checks...")
        url = "https://api.github.com/repos/prowler-cloud/prowler/contents/prowler/providers/aws/services"
        # Would parse Prowler's check definitions
        
    def fetch_aws_security_hub(self):
        """Fetch Security Hub control definitions"""
        print("Fetching Security Hub controls...")
        # In reality: boto3.client('securityhub').describe_standards_controls()
        
    def parse_control_spreadsheet(self, file_path):
        """Parse control spreadsheet you paste"""
        controls = []
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                control = self.analyze_control_pattern(row)
                controls.append(control)
        return controls
        
    def analyze_control_pattern(self, control_data):
        """Analyze control to determine interrogation pattern"""
        title = control_data.get('Title', '').lower()
        description = control_data.get('Description', '').lower()
        
        # Pattern matching
        patterns = {
            'public_access': ['public', 'internet', '0.0.0.0/0', 'publicly accessible'],
            'encryption': ['encrypt', 'tls', 'ssl', 'https', 'kms'],
            'logging': ['log', 'trail', 'flow log', 'audit'],
            'iam_policy': ['password', 'mfa', 'access key', 'credentials'],
            'network': ['security group', 'nacl', 'vpc', 'subnet'],
            'backup': ['backup', 'snapshot', 'retention'],
            'monitoring': ['alarm', 'metric', 'cloudwatch', 'config']
        }
        
        detected_pattern = 'generic'
        for pattern_name, keywords in patterns.items():
            if any(keyword in title or keyword in description for keyword in keywords):
                detected_pattern = pattern_name
                break
                
        return {
            'control_id': control_data.get('ControlId'),
            'title': control_data.get('Title'),
            'pattern': detected_pattern,
            'suggested_interrogator': self.pattern_to_interrogator(detected_pattern)
        }
        
    def pattern_to_interrogator(self, pattern):
        """Map pattern to interrogator class"""
        mapping = {
            'public_access': 'ResourcePublicAccessInterrogator',
            'encryption': 'EncryptionConfigInterrogator',
            'logging': 'LoggingConfigInterrogator',
            'iam_policy': 'IAMPolicyInterrogator',
            'network': 'NetworkSecurityInterrogator',
            'backup': 'BackupConfigInterrogator',
            'monitoring': 'ComplianceMonitoringInterrogator',
            'generic': 'ServiceConfigInterrogator'
        }
        return mapping.get(pattern, 'ServiceConfigInterrogator')

if __name__ == "__main__":
    grabber = SecurityControlGrabber()
    # Would fetch from various sources
    grabber.fetch_aws_security_hub()
    grabber.fetch_aws_config_rules()
    grabber.fetch_prowler_checks()
