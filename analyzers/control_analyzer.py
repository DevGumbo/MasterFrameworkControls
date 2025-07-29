#!/usr/bin/env python3
"""
Control Analysis Framework
Analyzes control patterns across standards to generate optimal interrogators
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict
import re
from dataclasses import dataclass

@dataclass
class ControlPattern:
    """Represents a common pattern across controls"""
    pattern_name: str
    controls: List[Dict]
    common_keywords: Set[str]
    aws_apis: Set[str]
    parameters: Dict[str, Set]

class ControlAnalyzer:
    """Analyzes controls to find patterns and generate interrogators"""
    
    def __init__(self, csv_dir: str):
        self.csv_dir = Path(csv_dir)
        self.all_controls = []
        self.patterns = defaultdict(ControlPattern)
        
    def analyze_all_standards(self):
        """Main analysis entry point"""
        # 1. Load all controls
        self._load_all_controls()
        
        # 2. Find semantic clusters
        clusters = self._cluster_controls()
        
        # 3. Extract common patterns
        patterns = self._extract_patterns(clusters)
        
        # 4. Design interrogators
        interrogator_design = self._design_interrogators(patterns)
        
        # 5. Generate report
        return self._generate_report(interrogator_design)
        
    def _load_all_controls(self):
        """Load all CSV files"""
        for csv_file in self.csv_dir.glob("*.csv"):
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    row['source_file'] = csv_file.name
                    row['standard'] = self._extract_standard(csv_file.name)
                    self.all_controls.append(row)
                    
    def _cluster_controls(self) -> Dict[str, List[Dict]]:
        """Group controls by semantic similarity"""
        clusters = defaultdict(list)
        
        # Define clustering rules
        cluster_rules = {
            'password_policy': ['password', 'length', 'reuse', 'expiry', 'complexity'],
            'mfa_authentication': ['mfa', 'multi-factor', 'authentication'],
            'access_keys': ['access key', 'key rotation', 'credentials'],
            'public_access': ['public', '0.0.0.0/0', 'internet', 'publicly accessible'],
            'encryption': ['encrypt', 'kms', 'tls', 'ssl', 'https'],
            'logging': ['log', 'trail', 'flow log', 'audit'],
            'network_security': ['security group', 'nacl', 'ingress', 'egress'],
            'backup': ['backup', 'retention', 'snapshot'],
            'monitoring': ['alarm', 'metric', 'cloudwatch', 'config']
        }
        
        # Classify each control
        for control in self.all_controls:
            title = control['Title'].lower()
            desc = control['Description'].lower()
            
            for cluster_name, keywords in cluster_rules.items():
                if any(kw in title or kw in desc for kw in keywords):
                    clusters[cluster_name].append(control)
                    break
            else:
                clusters['uncategorized'].append(control)
                
        return clusters
        
    def _extract_patterns(self, clusters: Dict[str, List[Dict]]) -> Dict[str, ControlPattern]:
        """Extract common patterns from clusters"""
        patterns = {}
        
        for cluster_name, controls in clusters.items():
            if not controls:
                continue
                
            # Find common keywords
            common_keywords = self._find_common_keywords(controls)
            
            # Identify AWS APIs needed
            aws_apis = self._identify_aws_apis(controls)
            
            # Extract parameter patterns
            parameters = self._extract_parameters(controls)
            
            patterns[cluster_name] = ControlPattern(
                pattern_name=cluster_name,
                controls=controls,
                common_keywords=common_keywords,
                aws_apis=aws_apis,
                parameters=parameters
            )
            
        return patterns
        
    def _find_common_keywords(self, controls: List[Dict]) -> Set[str]:
        """Find keywords common across controls"""
        if not controls:
            return set()
            
        # Get keywords from first control
        keywords = set(controls[0]['Title'].lower().split())
        
        # Find intersection with other controls
        for control in controls[1:]:
            control_keywords = set(control['Title'].lower().split())
            keywords = keywords.intersection(control_keywords)
            
        return keywords
        
    def _identify_aws_apis(self, controls: List[Dict]) -> Set[str]:
        """Identify AWS API calls needed"""
        api_mapping = {
            'password': ['iam:GetAccountPasswordPolicy', 'iam:UpdateAccountPasswordPolicy'],
            'mfa': ['iam:ListMFADevices', 'iam:GetAccountSummary'],
            'access key': ['iam:ListAccessKeys', 'iam:GetAccessKeyLastUsed'],
            'security group': ['ec2:DescribeSecurityGroups'],
            'encryption': ['kms:DescribeKey', 'ec2:GetEbsEncryptionByDefault'],
            'cloudtrail': ['cloudtrail:DescribeTrails', 'cloudtrail:GetTrailStatus'],
            'vpc flow': ['ec2:DescribeFlowLogs', 'ec2:DescribeVpcs']
        }
        
        apis = set()
        for control in controls:
            text = (control['Title'] + ' ' + control['Description']).lower()
            for keyword, api_list in api_mapping.items():
                if keyword in text:
                    apis.update(api_list)
                    
        return apis
        
    def _extract_parameters(self, controls: List[Dict]) -> Dict[str, Set]:
        """Extract common parameters"""
        params = defaultdict(set)
        
        for control in controls:
            # Extract numbers (like 90 days, 14 characters)
            numbers = re.findall(r'\d+', control['Title'] + ' ' + control['Description'])
            if numbers:
                params['numeric_values'].update(numbers)
                
            # Extract ports
            ports = re.findall(r'port[s]?\s+(\d+)', control['Title'] + ' ' + control['Description'], re.I)
            if ports:
                params['ports'].update(ports)
                
        return dict(params)
        
    def _design_interrogators(self, patterns: Dict[str, ControlPattern]) -> Dict[str, Dict]:
        """Design optimal interrogator structure"""
        interrogators = defaultdict(dict)
        
        # Group patterns by service
        for pattern_name, pattern in patterns.items():
            # Determine which interrogator should handle this
            interrogator_name = self._determine_interrogator(pattern)
            
            # Design method for this pattern
            method_design = {
                'handles_controls': [c['ControlId'] for c in pattern.controls],
                'common_checks': list(pattern.common_keywords),
                'required_apis': list(pattern.aws_apis),
                'parameters': dict(pattern.parameters),
                'control_count': len(pattern.controls)
            }
            
            interrogators[interrogator_name][pattern_name] = method_design
            
        return dict(interrogators)
        
    def _determine_interrogator(self, pattern: ControlPattern) -> str:
        """Determine which interrogator should handle this pattern"""
        # Map patterns to interrogators
        interrogator_map = {
            'password': 'IAMPolicyInterrogator',
            'mfa': 'IAMPolicyInterrogator', 
            'access': 'IAMPolicyInterrogator',
            'public': 'ResourcePublicAccessInterrogator',
            'encrypt': 'EncryptionConfigInterrogator',
            'log': 'LoggingConfigInterrogator',
            'security group': 'NetworkSecurityInterrogator',
            'monitor': 'ComplianceMonitoringInterrogator'
        }
        
        for keyword, interrogator in interrogator_map.items():
            if keyword in pattern.pattern_name:
                return interrogator
                
        return 'ServiceConfigInterrogator'
        
    def _generate_report(self, interrogator_design: Dict[str, Dict]) -> Dict:
        """Generate analysis report"""
        report = {
            'summary': {
                'total_controls': len(self.all_controls),
                'total_patterns': sum(len(methods) for methods in interrogator_design.values()),
                'interrogators_needed': len(interrogator_design)
            },
            'interrogator_design': interrogator_design,
            'uncategorized_controls': self._find_uncategorized()
        }
        
        return report
        
    def _find_uncategorized(self) -> List[Dict]:
        """Find controls that didn't fit any pattern"""
        # Implementation would track uncategorized controls
        return []
        
    def _extract_standard(self, filename: str) -> str:
        """Extract standard name from filename"""
        if 'cis_v1_2' in filename:
            return 'cis_v1_2'
        elif 'cis_v1_4' in filename:
            return 'cis_v1_4'
        elif 'cis_v3_0' in filename:
            return 'cis_v3_0'
        elif 'fsbp' in filename:
            return 'fsbp'
        return 'unknown'


def main():
    """Run control analysis"""
    analyzer = ControlAnalyzer('/Users/jonmiller/Documents/Projects/claude_inspection/cloud_control_framework/SecPolicies')
    report = analyzer.analyze_all_standards()
    
    # Save report
    with open('control_analysis_report.json', 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"Analysis complete. Found {report['summary']['total_patterns']} patterns across {report['summary']['total_controls']} controls")
    

if __name__ == "__main__":
    main()
