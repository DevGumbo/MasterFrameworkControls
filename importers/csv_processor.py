#!/usr/bin/env python3
"""
CSV Processor - Converts control CSVs to JSON format
"""

import csv
import json
from collections import defaultdict
from pathlib import Path
import re

class ControlCSVProcessor:
    """Processes control CSV files and generates JSON definitions"""
    
    def __init__(self):
        self.controls_by_service = defaultdict(list)
        self.standards_mapping = defaultdict(lambda: defaultdict(dict))
        self.unique_controls = {}  # Track unique controls across standards
        
    def process_csv_files(self, csv_files):
        """Process multiple CSV files"""
        for standard, filepath in csv_files.items():
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self._process_control(row, standard)
                    
    def _process_control(self, row, standard):
        """Process individual control from CSV"""
        # Create control key for deduplication
        title = row['Title']
        control_key = self._generate_control_key(title)
        
        # If this control already exists, just add the standard mapping
        if control_key in self.unique_controls:
            existing = self.unique_controls[control_key]
            existing['standards'][standard] = {
                'control_id': row['ControlId'],
                'severity': row['SeverityRating']
            }
        else:
            # Create new control
            control = {
                'control_id': control_key,
                'title': title,
                'description': row['Description'],
                'severity': row['SeverityRating'],
                'interrogation': self._determine_interrogation(row),
                'standards': {
                    standard: {
                        'control_id': row['ControlId'],
                        'severity': row['SeverityRating']
                    }
                }
            }
            
            self.unique_controls[control_key] = control
            service = self._determine_service(row)
            self.controls_by_service[service].append(control)
            
    def _generate_control_key(self, title):
        """Generate unique control ID from title"""
        # Extract service and create ID
        if 'IAM' in title or 'password' in title.lower() or 'MFA' in title:
            prefix = 'IAM'
        elif 'EC2' in title or 'VPC' in title or 'security group' in title.lower():
            prefix = 'EC2'
        elif 'S3' in title or 'bucket' in title.lower():
            prefix = 'S3'
        elif 'KMS' in title or 'CMK' in title:
            prefix = 'KMS'
        elif 'RDS' in title:
            prefix = 'RDS'
        elif 'CloudTrail' in title:
            prefix = 'CLOUDTRAIL'
        elif 'Config' in title or 'CloudWatch' in title:
            prefix = 'MONITORING'
        elif 'ELB' in title or 'Load Balancer' in title:
            prefix = 'ELB'
        else:
            prefix = 'AWS'
            
        # Create short hash from title
        import hashlib
        hash_val = hashlib.md5(title.encode()).hexdigest()[:6].upper()
        return f"{prefix}_{hash_val}"
        
    def _determine_service(self, control):
        """Determine AWS service from control"""
        control_id = control['ControlId'].upper()
        title = control['Title'].upper()
        
        if 'IAM' in control_id or 'PASSWORD' in title or 'MFA' in title:
            return 'iam'
        elif 'EC2' in control_id or 'VPC' in title or 'SECURITY GROUP' in title:
            return 'ec2'
        elif 'S3' in control_id or 'BUCKET' in title:
            return 's3'
        elif 'KMS' in control_id or 'CMK' in title:
            return 'kms'
        elif 'RDS' in control_id:
            return 'rds'
        elif 'CLOUDTRAIL' in control_id or 'CLOUDTRAIL' in title:
            return 'cloudtrail'
        elif 'CONFIG' in control_id or 'CLOUDWATCH' in control_id:
            return 'monitoring'
        elif 'ELB' in control_id:
            return 'elb'
        elif 'LAMBDA' in control_id:
            return 'lambda'
        elif 'CLOUDFRONT' in control_id:
            return 'cloudfront'
        else:
            return 'other'
            
    def _determine_interrogation(self, control):
        """Determine interrogation pattern"""
        title = control['Title'].lower()
        desc = control['Description'].lower()
        
        # Define interrogation patterns
        if any(term in title or term in desc for term in 
               ['password', 'mfa', 'multi-factor', 'credentials', 'access key']):
            return {
                'class': 'IAMPolicyInterrogator',
                'method': 'check_iam_policy',
                'parameters': self._extract_iam_params(control)
            }
        elif any(term in title or term in desc for term in 
                ['0.0.0.0/0', 'public', 'publicly accessible', 'internet']):
            return {
                'class': 'ResourcePublicAccessInterrogator',
                'method': 'check_public_access',
                'parameters': self._extract_public_params(control)
            }
        elif any(term in title or term in desc for term in 
                ['encrypt', 'kms', 'tls', 'ssl', 'https']):
            return {
                'class': 'EncryptionConfigInterrogator',
                'method': 'check_encryption',
                'parameters': self._extract_encryption_params(control)
            }
        elif any(term in title or term in desc for term in 
                ['log', 'trail', 'flow log', 'audit']):
            return {
                'class': 'LoggingConfigInterrogator',
                'method': 'check_logging',
                'parameters': self._extract_logging_params(control)
            }
        elif any(term in title or term in desc for term in 
                ['security group', 'nacl', 'network acl', 'vpc']):
            return {
                'class': 'NetworkSecurityInterrogator',
                'method': 'check_network_security',
                'parameters': self._extract_network_params(control)
            }
        elif any(term in title or term in desc for term in 
                ['config', 'cloudwatch', 'metric filter', 'alarm']):
            return {
                'class': 'ComplianceMonitoringInterrogator',
                'method': 'check_monitoring',
                'parameters': self._extract_monitoring_params(control)
            }
        else:
            return {
                'class': 'ServiceConfigInterrogator',
                'method': 'check_service_config',
                'parameters': {'check_type': 'general'}
            }
            
    def _extract_iam_params(self, control):
        """Extract IAM-specific parameters"""
        params = {}
        title = control['Title'].lower()
        
        if 'password' in title:
            if 'length' in title:
                params['check_type'] = 'password_length'
                params['min_length'] = 14
            elif 'reuse' in title:
                params['check_type'] = 'password_reuse'
            elif 'expire' in title:
                params['check_type'] = 'password_expiry'
                params['max_days'] = 90
        elif 'mfa' in title:
            params['check_type'] = 'mfa_enabled'
            if 'root' in title:
                params['user_type'] = 'root'
        elif 'access key' in title:
            params['check_type'] = 'access_key_rotation'
            params['max_days'] = 90
            
        return params
        
    def _extract_public_params(self, control):
        """Extract public access parameters"""
        params = {}
        title = control['Title'].lower()
        
        if 's3' in title or 'bucket' in title:
            params['resource_type'] = 'S3Bucket'
            params['check_type'] = 'block_public_access'
        elif 'security group' in title:
            params['resource_type'] = 'SecurityGroup'
            params['check_type'] = 'ingress_rules'
            if '22' in title:
                params['ports'] = [22]
            elif '3389' in title:
                params['ports'] = [3389]
        elif 'snapshot' in title:
            params['resource_type'] = 'EBSSnapshot'
            params['check_type'] = 'public_sharing'
            
        return params
        
    def _extract_encryption_params(self, control):
        """Extract encryption parameters"""
        params = {}
        title = control['Title'].lower()
        
        if 'at rest' in title or 'at-rest' in title:
            params['encryption_type'] = 'at_rest'
        elif 'in transit' in title:
            params['encryption_type'] = 'in_transit'
        else:
            params['encryption_type'] = 'both'
            
        if 'kms' in title:
            params['key_type'] = 'customer_managed'
        else:
            params['key_type'] = 'any'
            
        return params
        
    def _extract_logging_params(self, control):
        """Extract logging parameters"""
        params = {}
        title = control['Title'].lower()
        
        if 'cloudtrail' in title:
            params['service'] = 'cloudtrail'
            if 'validation' in title:
                params['check_type'] = 'log_validation'
            elif 'multi-region' in title:
                params['check_type'] = 'multi_region'
        elif 'vpc flow' in title:
            params['service'] = 'vpc_flow_logs'
            params['check_type'] = 'enabled'
        elif 's3' in title and 'logging' in title:
            params['service'] = 's3'
            params['check_type'] = 'access_logging'
            
        return params
        
    def _extract_network_params(self, control):
        """Extract network security parameters"""
        params = {}
        title = control['Title'].lower()
        
        if 'default security group' in title:
            params['check_type'] = 'default_sg_rules'
        elif 'nacl' in title or 'network acl' in title:
            params['check_type'] = 'nacl_rules'
            if '22' in title or '3389' in title:
                params['ports'] = [22, 3389]
                
        return params
        
    def _extract_monitoring_params(self, control):
        """Extract monitoring parameters"""
        params = {}
        title = control['Title'].lower()
        
        if 'metric filter' in title:
            params['check_type'] = 'metric_filter'
            if 'unauthorized' in title:
                params['filter_type'] = 'unauthorized_api'
            elif 'root' in title:
                params['filter_type'] = 'root_usage'
        elif 'config' in title:
            params['check_type'] = 'aws_config_enabled'
            
        return params
        
    def save_control_definitions(self, output_dir):
        """Save control definitions to JSON files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save controls by service
        for service, controls in self.controls_by_service.items():
            if controls:  # Only save if there are controls
                filename = output_path / f"{service}_controls.json"
                with open(filename, 'w') as f:
                    json.dump({
                        'service': service,
                        'controls': controls
                    }, f, indent=2)
                print(f"Saved {len(controls)} controls to {filename}")
                
    def save_standards_mappings(self, output_dir):
        """Save standards mappings"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create reverse mappings
        for control_id, control in self.unique_controls.items():
            for standard, std_info in control['standards'].items():
                mapping_file = output_path / f"{standard.replace('.', '_')}_mapping.json"
                
                if mapping_file.exists():
                    with open(mapping_file, 'r') as f:
                        mappings = json.load(f)
                else:
                    mappings = {}
                    
                mappings[std_info['control_id']] = control_id
                
                with open(mapping_file, 'w') as f:
                    json.dump(mappings, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    # Process the CSV files
    processor = ControlCSVProcessor()
    
    csv_files = {
        'cis_v1_2': '/Users/jonmiller/Documents/Projects/claude_inspection/cloud_control_framework/SecPolicies/cis_cis-aws-foundations-benchmark_v1_2_0_controls.csv',
        'cis_v1_4': '/Users/jonmiller/Documents/Projects/claude_inspection/cloud_control_framework/SecPolicies/cis_cis-aws-foundations-benchmark_v1_4_0_controls.csv',
        'cis_v3_0': '/Users/jonmiller/Documents/Projects/claude_inspection/cloud_control_framework/SecPolicies/cis_cis-aws-foundations-benchmark_v3_0_0_controls.csv',
        'fsbp': '/Users/jonmiller/Documents/Projects/claude_inspection/cloud_control_framework/SecPolicies/fsbp_aws-foundational-security-best-practices_v1_0_0_controls.csv'
    }
    
    processor.process_csv_files(csv_files)
    processor.save_control_definitions('/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/control_definitions/aws')
    processor.save_standards_mappings('/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/control_definitions/standards')
