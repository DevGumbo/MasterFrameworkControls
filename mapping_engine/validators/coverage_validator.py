#!/usr/bin/env python3
"""
Coverage Validator
Ensures every control has a working interrogator mapping
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple,Any
from collections import defaultdict

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))


class CoverageValidator:
    """Validates that all controls have working interrogator mappings"""
    
    def __init__(self, control_dir: str, interrogator_dir: str):
        self.control_dir = Path(control_dir)
        self.interrogator_dir = Path(interrogator_dir)
        self.validation_results = {
            'valid': [],
            'invalid': [],
            'warnings': []
        }
        
    def validate_coverage(self) -> Dict[str, Any]:
        """Main validation process"""
        # 1. Load all controls
        controls = self._load_all_controls()
        
        # 2. Discover available interrogators
        available_interrogators = self._discover_interrogators()
        
        # 3. Validate each control
        for control in controls:
            self._validate_control(control, available_interrogators)
            
        # 4. Generate validation report
        report = self._generate_report(controls, available_interrogators)
        
        return report
        
    def _load_all_controls(self) -> List[Dict]:
        """Load all control definitions"""
        controls = []
        
        for json_file in self.control_dir.glob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    for control in data.get('controls', []):
                        control['source_file'] = json_file.name
                        controls.append(control)
            except Exception as e:
                self.validation_results['warnings'].append({
                    'type': 'file_error',
                    'file': str(json_file),
                    'error': str(e)
                })
                
        return controls
        
    def _discover_interrogators(self) -> Dict[str, Set[str]]:
        """Discover available interrogators and their methods"""
        interrogators = {}
        
        # First, try to dynamically import and inspect
        try:
            from framework.interrogator_registry import InterrogatorRegistry
            registry = InterrogatorRegistry()
            discovered = registry.discover(str(self.interrogator_dir.parent))
            
            for name, interrogator_class in discovered.items():
                methods = set()
                # Get check types from the actual class
                instance = interrogator_class({'region': 'us-east-1', 'account_ids': []})
                
                # Look for _check_* methods
                for attr in dir(instance):
                    if attr.startswith('_check_'):
                        check_type = attr.replace('_check_', '')
                        methods.add(check_type)
                        
                interrogators[name] = methods
        except:
            # Fallback: parse files statically
            interrogators = self._static_interrogator_discovery()
            
        return interrogators
        
    def _static_interrogator_discovery(self) -> Dict[str, Set[str]]:
        """Static parsing fallback for interrogator discovery"""
        interrogators = {}
        
        for py_file in self.interrogator_dir.glob("*.py"):
            if py_file.name.startswith('__'):
                continue
                
            class_name = None
            check_types = set()
            
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    
                # Find class name
                import re
                class_match = re.search(r'class\s+(\w+)\s*\(.*BaseInterrogator', content)
                if class_match:
                    class_name = class_match.group(1)
                    
                # Find check types in execute method
                check_type_matches = re.findall(r'check_type\s*==\s*[\'"]([^\'\"]+)[\'"]', content)
                check_types.update(check_type_matches)
                
                # Find _check_* methods
                method_matches = re.findall(r'def\s+(_check_\w+)\s*\(', content)
                for method in method_matches:
                    check_type = method.replace('_check_', '')
                    check_types.add(check_type)
                    
                if class_name:
                    interrogators[class_name] = check_types
                    
            except Exception as e:
                self.validation_results['warnings'].append({
                    'type': 'interrogator_parse_error',
                    'file': str(py_file),
                    'error': str(e)
                })
                
        return interrogators
        
    def _validate_control(self, control: Dict, available_interrogators: Dict[str, Set[str]]):
        """Validate a single control"""
        control_id = control['control_id']
        interrogation = control.get('interrogation', {})
        
        # Check required fields
        if not interrogation:
            self.validation_results['invalid'].append({
                'control_id': control_id,
                'reason': 'Missing interrogation configuration',
                'severity': 'critical'
            })
            return
            
        interrogator_class = interrogation.get('class')
        parameters = interrogation.get('parameters', {})
        check_type = parameters.get('check_type', '')
        
        # Validate interrogator exists
        if not interrogator_class:
            self.validation_results['invalid'].append({
                'control_id': control_id,
                'reason': 'No interrogator class specified',
                'severity': 'critical'
            })
            return
            
        if interrogator_class not in available_interrogators:
            self.validation_results['invalid'].append({
                'control_id': control_id,
                'reason': f'Interrogator {interrogator_class} not found',
                'severity': 'critical',
                'interrogator': interrogator_class
            })
            return
            
        # Validate check_type if specified
        if check_type:
            available_check_types = available_interrogators[interrogator_class]
            if check_type not in available_check_types:
                self.validation_results['invalid'].append({
                    'control_id': control_id,
                    'reason': f'Check type "{check_type}" not found in {interrogator_class}',
                    'severity': 'high',
                    'interrogator': interrogator_class,
                    'check_type': check_type,
                    'available_check_types': list(available_check_types)
                })
                return
                
        # Validate required parameters
        validation_warnings = self._validate_parameters(control, interrogator_class, check_type)
        if validation_warnings:
            self.validation_results['warnings'].extend(validation_warnings)
        else:
            self.validation_results['valid'].append({
                'control_id': control_id,
                'interrogator': interrogator_class,
                'check_type': check_type
            })
            
    def _validate_parameters(self, control: Dict, interrogator_class: str, 
                           check_type: str) -> List[Dict]:
        """Validate control parameters"""
        warnings = []
        params = control['interrogation'].get('parameters', {})
        
        # Check for common required parameters based on interrogator type
        if 'Public' in interrogator_class and 'resource_type' not in params:
            warnings.append({
                'control_id': control['control_id'],
                'type': 'missing_parameter',
                'parameter': 'resource_type',
                'severity': 'medium'
            })
            
        if 'Network' in interrogator_class and check_type == 'ingress_rules':
            if 'ports' not in params and 'port' not in control.get('metadata', {}):
                warnings.append({
                    'control_id': control['control_id'],
                    'type': 'missing_parameter',
                    'parameter': 'ports',
                    'severity': 'low'
                })
                
        return warnings
        
    def _generate_report(self, controls: List[Dict], 
                        available_interrogators: Dict[str, Set[str]]) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        # Group invalid controls by reason
        invalid_by_reason = defaultdict(list)
        for invalid in self.validation_results['invalid']:
            reason = invalid['reason']
            invalid_by_reason[reason].append(invalid)
            
        # Calculate coverage statistics
        total_controls = len(controls)
        valid_controls = len(self.validation_results['valid'])
        invalid_controls = len(self.validation_results['invalid'])
        coverage_percentage = (valid_controls / total_controls * 100) if total_controls > 0 else 0
        
        report = {
            'summary': {
                'total_controls': total_controls,
                'valid_controls': valid_controls,
                'invalid_controls': invalid_controls,
                'warnings': len(self.validation_results['warnings']),
                'coverage_percentage': round(coverage_percentage, 2),
                'available_interrogators': len(available_interrogators)
            },
            'invalid_controls': self.validation_results['invalid'],
            'warnings': self.validation_results['warnings'],
            'invalid_by_reason': dict(invalid_by_reason),
            'missing_interrogators': self._find_missing_interrogators(),
            'interrogator_usage': self._calculate_interrogator_usage()
        }
        
        return report
        
    def _find_missing_interrogators(self) -> List[str]:
        """Find interrogators referenced but not available"""
        referenced = set()
        
        for invalid in self.validation_results['invalid']:
            if 'interrogator' in invalid and 'not found' in invalid['reason']:
                referenced.add(invalid['interrogator'])
                
        return sorted(list(referenced))
        
    def _calculate_interrogator_usage(self) -> Dict[str, int]:
        """Calculate how many controls use each interrogator"""
        usage = defaultdict(int)
        
        for valid in self.validation_results['valid']:
            usage[valid['interrogator']] += 1
            
        for invalid in self.validation_results['invalid']:
            if 'interrogator' in invalid:
                usage[invalid['interrogator']] += 1
                
        return dict(usage)
        
    def generate_fix_script(self, report: Dict[str, Any], output_file: str):
        """Generate a script to fix common issues"""
        fixes = []
        
        # Group fixes by type
        for invalid in report['invalid_controls']:
            control_id = invalid['control_id']
            reason = invalid['reason']
            
            if 'not found' in reason and 'Interrogator' in reason:
                fixes.append(f"# Control {control_id} needs interrogator: {invalid.get('interrogator', 'Unknown')}")
                fixes.append(f"# Consider mapping to an existing interrogator or creating a new one\n")
            elif 'Check type' in reason:
                fixes.append(f"# Control {control_id} needs method '{invalid['check_type']}' in {invalid['interrogator']}")
                fixes.append(f"# Available methods: {', '.join(invalid.get('available_check_types', []))}\n")
                
        # Write fix script
        with open(output_file, 'w') as f:
            f.write("#!/usr/bin/env python3\n")
            f.write("# Auto-generated fix suggestions\n\n")
            f.write("\n".join(fixes))
            
        print(f"Generated fix suggestions in {output_file}")


if __name__ == "__main__":
    # Run validation
    validator = CoverageValidator(
        control_dir='/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/control_definitions/aws',
        interrogator_dir='/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/interrogators/aws'
    )
    
    report = validator.validate_coverage()
    
    # Save report
    with open('coverage_report.json', 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"Coverage Validation Report:")
    print(f"- Total controls: {report['summary']['total_controls']}")
    print(f"- Valid controls: {report['summary']['valid_controls']}")
    print(f"- Invalid controls: {report['summary']['invalid_controls']}")
    print(f"- Coverage: {report['summary']['coverage_percentage']}%")
    
    if report['missing_interrogators']:
        print(f"\nMissing Interrogators:")
        for interrogator in report['missing_interrogators']:
            print(f"  - {interrogator}")
            
    # Generate fix script if there are issues
    if report['invalid_controls']:
        validator.generate_fix_script(report, 'coverage_fixes.py')
