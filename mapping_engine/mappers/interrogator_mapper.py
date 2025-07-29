#!/usr/bin/env python3
"""
Interrogator Mapper
Maps controls to existing interrogators and identifies gaps
"""

import json
import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional,Any
from collections import defaultdict
import inspect
import importlib.util


class InterrogatorMapper:
    """Maps controls to interrogators intelligently"""
    
    def __init__(self, control_dir: str, interrogator_dir: str):
        self.control_dir = Path(control_dir)
        self.interrogator_dir = Path(interrogator_dir)
        self.available_interrogators = {}
        self.control_mappings = {}
        self.unmapped_controls = []
        
    def analyze_and_map(self) -> Dict[str, Any]:
        """Main mapping process"""
        # 1. Discover available interrogators
        self._discover_interrogators()
        
        # 2. Load all controls
        controls = self._load_controls()
        
        # 3. Map controls to interrogators
        mapping_results = self._map_controls(controls)
        
        # 4. Generate mapping report
        report = self._generate_report(mapping_results)
        
        return report
        
    def _discover_interrogators(self):
        """Scan interrogator directory to understand capabilities"""
        for py_file in self.interrogator_dir.glob("*.py"):
            if py_file.name.startswith('__'):
                continue
                
            try:
                # Parse the Python file to extract class and method info
                with open(py_file, 'r') as f:
                    tree = ast.parse(f.read())
                    
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        # Found an interrogator class
                        interrogator_info = {
                            'file': py_file.name,
                            'methods': [],
                            'check_types': [],
                            'capabilities': []
                        }
                        
                        # Extract methods and check types
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef):
                                if item.name.startswith('_check_'):
                                    check_type = item.name.replace('_check_', '')
                                    interrogator_info['check_types'].append(check_type)
                                    
                                interrogator_info['methods'].append(item.name)
                                
                        # Look for check_type handling in execute method
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef) and item.name == 'execute':
                                check_types = self._extract_check_types_from_execute(item)
                                interrogator_info['check_types'].extend(check_types)
                                
                        self.available_interrogators[node.name] = interrogator_info
                        
            except Exception as e:
                print(f"Error parsing {py_file}: {e}")
                
    def _extract_check_types_from_execute(self, func_node: ast.FunctionDef) -> List[str]:
        """Extract check_type values from execute method"""
        check_types = []
        
        for node in ast.walk(func_node):
            # Look for: if check_type == 'some_value':
            if isinstance(node, ast.Compare):
                if (isinstance(node.left, ast.Name) and node.left.id == 'check_type' and
                    isinstance(node.comparators[0], ast.Str)):
                    check_types.append(node.comparators[0].s)
            # Python 3.8+ uses ast.Constant instead of ast.Str
            elif isinstance(node, ast.Compare):
                if (isinstance(node.left, ast.Name) and node.left.id == 'check_type' and
                    isinstance(node.comparators[0], ast.Constant) and 
                    isinstance(node.comparators[0].value, str)):
                    check_types.append(node.comparators[0].value)
                    
        return check_types
        
    def _load_controls(self) -> List[Dict]:
        """Load all control definitions"""
        controls = []
        
        for json_file in self.control_dir.glob("*.json"):
            with open(json_file, 'r') as f:
                data = json.load(f)
                controls.extend(data.get('controls', []))
                
        return controls
        
    def _map_controls(self, controls: List[Dict]) -> Dict[str, Any]:
        """Map each control to appropriate interrogator"""
        results = {
            'mapped': [],
            'unmapped': [],
            'remapped': [],
            'new_methods_needed': defaultdict(list)
        }
        
        for control in controls:
            mapping = self._map_single_control(control)
            
            if mapping['status'] == 'mapped':
                results['mapped'].append(mapping)
            elif mapping['status'] == 'unmapped':
                results['unmapped'].append(mapping)
            elif mapping['status'] == 'remapped':
                results['remapped'].append(mapping)
            elif mapping['status'] == 'needs_new_method':
                interrogator = mapping['suggested_interrogator']
                results['new_methods_needed'][interrogator].append(mapping)
                
        return results
        
    def _map_single_control(self, control: Dict) -> Dict[str, Any]:
        """Map a single control to interrogator"""
        current_interrogator = control['interrogation']['class']
        current_check_type = control['interrogation']['parameters'].get('check_type', '')
        
        # Check if current mapping is valid
        if current_interrogator in self.available_interrogators:
            interrogator_info = self.available_interrogators[current_interrogator]
            
            # Check if the check_type is supported
            if not current_check_type or current_check_type in interrogator_info['check_types']:
                return {
                    'status': 'mapped',
                    'control_id': control['control_id'],
                    'interrogator': current_interrogator,
                    'check_type': current_check_type
                }
            else:
                # Interrogator exists but doesn't support this check_type
                return {
                    'status': 'needs_new_method',
                    'control_id': control['control_id'],
                    'current_interrogator': current_interrogator,
                    'suggested_interrogator': current_interrogator,
                    'needed_check_type': current_check_type,
                    'reason': f"Check type '{current_check_type}' not found in interrogator"
                }
        
        # Try to find a better mapping
        suggested = self._suggest_interrogator(control)
        
        if suggested:
            return {
                'status': 'remapped',
                'control_id': control['control_id'],
                'old_interrogator': current_interrogator,
                'new_interrogator': suggested['interrogator'],
                'new_check_type': suggested['check_type'],
                'reason': suggested['reason']
            }
        else:
            return {
                'status': 'unmapped',
                'control_id': control['control_id'],
                'title': control['title'],
                'current_interrogator': current_interrogator,
                'reason': 'No suitable interrogator found'
            }
            
    def _suggest_interrogator(self, control: Dict) -> Optional[Dict[str, str]]:
        """Suggest best interrogator for a control"""
        title = control['title'].lower()
        desc = control.get('description', '').lower()
        metadata = control.get('metadata', {})
        
        # Pattern matching for interrogator selection
        patterns = {
            'IAMPolicyInterrogator': {
                'keywords': ['password', 'mfa', 'access key', 'credentials', 'iam'],
                'check_types': {
                    'password_length': ['length', 'minimum', 'characters'],
                    'password_reuse': ['reuse', 'prevent'],
                    'password_expiry': ['expir', 'days', 'max'],
                    'mfa_enabled': ['mfa', 'multi-factor'],
                    'access_key_rotation': ['rotation', 'rotate', '90 days'],
                    'root_access_keys': ['root', 'access key']
                }
            },
            'NetworkSecurityInterrogator': {
                'keywords': ['security group', 'nacl', 'network', 'ingress', 'egress'],
                'check_types': {
                    'ingress_rules': ['ingress', '0.0.0.0/0', 'port'],
                    'default_sg_rules': ['default', 'security group'],
                    'nacl_rules': ['nacl', 'network acl']
                }
            },
            'ResourcePublicAccessInterrogator': {
                'keywords': ['public', 'internet', 'accessible', '0.0.0.0/0'],
                'check_types': {
                    'public_access': ['public', 'accessible'],
                    's3_public': ['s3', 'bucket', 'public'],
                    'snapshot_public': ['snapshot', 'public'],
                    'rds_public': ['rds', 'database', 'public']
                }
            }
        }
        
        best_match = None
        best_score = 0
        
        for interrogator, pattern_info in patterns.items():
            if interrogator not in self.available_interrogators:
                continue
                
            # Check if any keywords match
            keyword_score = sum(1 for kw in pattern_info['keywords'] if kw in title or kw in desc)
            
            if keyword_score > best_score:
                # Find best check_type
                for check_type, check_keywords in pattern_info['check_types'].items():
                    check_score = sum(1 for kw in check_keywords if kw in title or kw in desc)
                    
                    if check_score > 0:
                        best_match = {
                            'interrogator': interrogator,
                            'check_type': check_type,
                            'reason': f"Matched keywords: {', '.join(kw for kw in check_keywords if kw in title or kw in desc)}"
                        }
                        best_score = keyword_score + check_score
                        
        return best_match
        
    def _generate_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive mapping report"""
        report = {
            'summary': {
                'total_controls': sum(len(v) if isinstance(v, list) else sum(len(controls) for controls in v.values()) 
                                    for v in results.values()),
                'mapped_controls': len(results['mapped']),
                'remapped_controls': len(results['remapped']),
                'unmapped_controls': len(results['unmapped']),
                'interrogators_needing_methods': len(results['new_methods_needed'])
            },
            'mapped_controls': results['mapped'],
            'remapped_controls': results['remapped'],
            'unmapped_controls': results['unmapped'],
            'new_methods_needed': dict(results['new_methods_needed']),
            'available_interrogators': self._summarize_interrogators()
        }
        
        return report
        
    def _summarize_interrogators(self) -> Dict[str, Dict]:
        """Summarize available interrogators and their capabilities"""
        summary = {}
        
        for name, info in self.available_interrogators.items():
            summary[name] = {
                'file': info['file'],
                'check_types': list(set(info['check_types'])),
                'method_count': len(info['methods'])
            }
            
        return summary
        
    def generate_corrected_controls(self, mapping_report: Dict[str, Any], output_dir: str):
        """Generate corrected control files with proper mappings"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Load original controls by file
        controls_by_file = defaultdict(list)
        
        for json_file in self.control_dir.glob("*.json"):
            with open(json_file, 'r') as f:
                data = json.load(f)
                service = data.get('service', 'unknown')
                
                # Apply remappings
                for control in data.get('controls', []):
                    control_id = control['control_id']
                    
                    # Check if this control was remapped
                    for remapping in mapping_report['remapped_controls']:
                        if remapping['control_id'] == control_id:
                            control['interrogation']['class'] = remapping['new_interrogator']
                            control['interrogation']['parameters']['check_type'] = remapping['new_check_type']
                            control['mapping_notes'] = f"Remapped: {remapping['reason']}"
                            
                    controls_by_file[service].append(control)
                    
        # Save corrected files
        for service, controls in controls_by_file.items():
            output_file = output_path / f"{service}_controls.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'service': service,
                    'controls': controls
                }, f, indent=2)
                
        print(f"Generated corrected control files in {output_path}")


if __name__ == "__main__":
    # Test mapping
    mapper = InterrogatorMapper(
        control_dir='/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/control_definitions/aws',
        interrogator_dir='/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/interrogators/aws'
    )
    
    report = mapper.analyze_and_map()
    
    # Save report
    with open('mapping_report.json', 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"Interrogator Mapping Analysis:")
    print(f"- Mapped controls: {report['summary']['mapped_controls']}")
    print(f"- Remapped controls: {report['summary']['remapped_controls']}")
    print(f"- Unmapped controls: {report['summary']['unmapped_controls']}")
    print(f"- Interrogators needing new methods: {report['summary']['interrogators_needing_methods']}")
    
    # Show what methods are needed
    if report['new_methods_needed']:
        print("\nNew Methods Needed:")
        for interrogator, controls in report['new_methods_needed'].items():
            print(f"\n{interrogator}:")
            for control in controls[:3]:  # Show first 3
                print(f"  - {control['needed_check_type']} for {control['control_id']}")
