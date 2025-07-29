#!/usr/bin/env python3
"""
Control Deduplication Analyzer
Finds controls across standards that check the same thing
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple,Any
from collections import defaultdict
import difflib


class ControlDeduplicator:
    """Analyze controls to find duplicates and conflicts"""
    
    def __init__(self, control_dir: str):
        self.control_dir = Path(control_dir)
        self.all_controls = []
        self.duplicates = defaultdict(list)
        self.conflicts = []
        
    def analyze_duplicates(self) -> Dict[str, Any]:
        """Main analysis entry point"""
        # Load all controls
        self._load_all_controls()
        
        # Find semantic duplicates
        duplicate_groups = self._find_semantic_duplicates()
        
        # Find parameter conflicts
        conflicts = self._find_conflicts(duplicate_groups)
        
        # Generate deduplication report
        report = self._generate_report(duplicate_groups, conflicts)
        
        return report
        
    def _load_all_controls(self):
        """Load all control JSON files"""
        for json_file in self.control_dir.glob("*.json"):
            with open(json_file, 'r') as f:
                data = json.load(f)
                for control in data.get('controls', []):
                    control['source_file'] = json_file.name
                    self.all_controls.append(control)
                    
    def _find_semantic_duplicates(self) -> Dict[str, List[Dict]]:
        """Find controls that check the same thing"""
        duplicate_groups = defaultdict(list)
        
        # Group by similar titles
        processed = set()
        
        for i, control1 in enumerate(self.all_controls):
            if control1['control_id'] in processed:
                continue
                
            group_key = f"group_{i}"
            duplicate_groups[group_key].append(control1)
            processed.add(control1['control_id'])
            
            # Find similar controls
            for control2 in self.all_controls[i+1:]:
                if control2['control_id'] in processed:
                    continue
                    
                similarity = self._calculate_similarity(control1, control2)
                if similarity > 0.85:  # 85% similar
                    duplicate_groups[group_key].append(control2)
                    processed.add(control2['control_id'])
                    
        # Filter out single-item groups
        return {k: v for k, v in duplicate_groups.items() if len(v) > 1}
        
    def _calculate_similarity(self, control1: Dict, control2: Dict) -> float:
        """Calculate semantic similarity between two controls"""
        # Compare titles
        title_similarity = difflib.SequenceMatcher(
            None, 
            control1['title'].lower(), 
            control2['title'].lower()
        ).ratio()
        
        # Compare descriptions
        desc_similarity = difflib.SequenceMatcher(
            None,
            control1['description'].lower(),
            control2['description'].lower()
        ).ratio()
        
        # Check if they have the same interrogation class
        same_class = (control1['interrogation']['class'] == 
                     control2['interrogation']['class'])
        
        # Check if they have similar parameters
        params1 = control1['interrogation'].get('parameters', {})
        params2 = control2['interrogation'].get('parameters', {})
        param_similarity = self._compare_parameters(params1, params2)
        
        # Weighted average
        weights = {
            'title': 0.4,
            'description': 0.3,
            'class': 0.2,
            'parameters': 0.1
        }
        
        similarity = (
            weights['title'] * title_similarity +
            weights['description'] * desc_similarity +
            weights['class'] * (1.0 if same_class else 0.0) +
            weights['parameters'] * param_similarity
        )
        
        return similarity
        
    def _compare_parameters(self, params1: Dict, params2: Dict) -> float:
        """Compare parameter dictionaries"""
        if not params1 and not params2:
            return 1.0
        if not params1 or not params2:
            return 0.0
            
        # Check common keys
        keys1 = set(params1.keys())
        keys2 = set(params2.keys())
        common_keys = keys1.intersection(keys2)
        
        if not keys1.union(keys2):
            return 1.0
            
        # Jaccard similarity of keys
        key_similarity = len(common_keys) / len(keys1.union(keys2))
        
        # Check if values match for common keys
        value_matches = 0
        for key in common_keys:
            if params1[key] == params2[key]:
                value_matches += 1
                
        value_similarity = value_matches / len(common_keys) if common_keys else 0
        
        return (key_similarity + value_similarity) / 2
        
    def _find_conflicts(self, duplicate_groups: Dict[str, List[Dict]]) -> List[Dict]:
        """Find controls with conflicting requirements"""
        conflicts = []
        
        for group_key, controls in duplicate_groups.items():
            # Check for parameter conflicts
            param_conflicts = self._check_parameter_conflicts(controls)
            if param_conflicts:
                conflicts.append({
                    'type': 'parameter_mismatch',
                    'controls': [c['control_id'] for c in controls],
                    'conflicts': param_conflicts
                })
                
            # Check for severity conflicts
            severities = set(c['severity'] for c in controls)
            if len(severities) > 1:
                conflicts.append({
                    'type': 'severity_mismatch',
                    'controls': [c['control_id'] for c in controls],
                    'severities': list(severities)
                })
                
        return conflicts
        
    def _check_parameter_conflicts(self, controls: List[Dict]) -> List[Dict]:
        """Check for conflicting parameters in similar controls"""
        conflicts = []
        
        # Extract all numeric parameters
        numeric_params = defaultdict(list)
        
        for control in controls:
            params = control['interrogation'].get('parameters', {})
            metadata = control.get('metadata', {})
            
            # Check days parameters
            if 'days' in metadata:
                for days in metadata['days']:
                    numeric_params['days'].append({
                        'control': control['control_id'],
                        'value': days,
                        'standards': list(control['standards'].keys())
                    })
                    
            # Check numeric thresholds
            for key, value in params.items():
                if isinstance(value, (int, float)):
                    numeric_params[key].append({
                        'control': control['control_id'],
                        'value': value,
                        'standards': list(control['standards'].keys())
                    })
                    
        # Find conflicts
        for param_name, values in numeric_params.items():
            unique_values = set(v['value'] for v in values)
            if len(unique_values) > 1:
                conflicts.append({
                    'parameter': param_name,
                    'values': values
                })
                
        return conflicts
        
    def _generate_report(self, duplicate_groups: Dict[str, List[Dict]], 
                        conflicts: List[Dict]) -> Dict[str, Any]:
        """Generate deduplication report"""
        report = {
            'summary': {
                'total_controls': len(self.all_controls),
                'duplicate_groups': len(duplicate_groups),
                'controls_with_duplicates': sum(len(g) for g in duplicate_groups.values()),
                'conflicts_found': len(conflicts)
            },
            'duplicate_groups': [],
            'conflicts': conflicts,
            'recommendations': []
        }
        
        # Process duplicate groups
        for group_key, controls in duplicate_groups.items():
            group_info = {
                'controls': [{
                    'control_id': c['control_id'],
                    'title': c['title'],
                    'standards': list(c['standards'].keys()),
                    'interrogator': c['interrogation']['class']
                } for c in controls],
                'suggested_master': self._suggest_master_control(controls)
            }
            report['duplicate_groups'].append(group_info)
            
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(duplicate_groups, conflicts)
        
        return report
        
    def _suggest_master_control(self, controls: List[Dict]) -> str:
        """Suggest which control should be the master"""
        # Prefer control that appears in most standards
        control_standards = [(c['control_id'], len(c['standards'])) for c in controls]
        control_standards.sort(key=lambda x: x[1], reverse=True)
        
        return control_standards[0][0]
        
    def _generate_recommendations(self, duplicate_groups: Dict[str, List[Dict]], 
                                conflicts: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Duplicate handling recommendations
        if duplicate_groups:
            recommendations.append(
                f"Found {len(duplicate_groups)} groups of duplicate controls. "
                "Consider consolidating these to use the same interrogator methods."
            )
            
        # Conflict resolution recommendations
        for conflict in conflicts:
            if conflict['type'] == 'parameter_mismatch':
                recommendations.append(
                    f"Parameter conflict in {conflict['parameter']}: "
                    "Consider using the most restrictive value or making it configurable."
                )
            elif conflict['type'] == 'severity_mismatch':
                recommendations.append(
                    f"Severity mismatch for duplicate controls: {conflict['severities']}. "
                    "Consider using the highest severity."
                )
                
        return recommendations
        
    def suggest_consolidations(self) -> Dict[str, List[str]]:
        """Suggest which controls can share the same interrogator method"""
        consolidations = defaultdict(list)
        
        for group_key, controls in self._find_semantic_duplicates().items():
            # Group by interrogation pattern
            by_pattern = defaultdict(list)
            
            for control in controls:
                pattern = (
                    control['interrogation']['class'],
                    control['interrogation']['parameters'].get('check_type', 'default')
                )
                by_pattern[pattern].append(control['control_id'])
                
            # Suggest consolidations
            for pattern, control_ids in by_pattern.items():
                if len(control_ids) > 1:
                    consolidation_key = f"{pattern[0]}.{pattern[1]}"
                    consolidations[consolidation_key].extend(control_ids)
                    
        return dict(consolidations)


if __name__ == "__main__":
    # Test with current control definitions
    deduplicator = ControlDeduplicator(
        '/Users/jonmiller/Documents/Projects/claude_inspection/MasterFrameworkControls/control_definitions/aws'
    )
    
    report = deduplicator.analyze_duplicates()
    
    # Save report
    with open('deduplication_report.json', 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"Deduplication Analysis Complete:")
    print(f"- Total controls: {report['summary']['total_controls']}")
    print(f"- Duplicate groups: {report['summary']['duplicate_groups']}")
    print(f"- Conflicts found: {report['summary']['conflicts_found']}")
    
    # Show consolidation suggestions
    consolidations = deduplicator.suggest_consolidations()
    if consolidations:
        print(f"\nSuggested Consolidations:")
        for method, controls in consolidations.items():
            print(f"  {method}: {len(controls)} controls can share this method")
