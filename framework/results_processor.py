"""
Results Processor
Processes and formats interrogation results
"""

import logging
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class ResultsProcessor:
    """Processes interrogation results"""
    
    def process(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process raw results into summary format
        
        Args:
            results: List of control execution results
            
        Returns:
            Processed results
        """
        # Group results by service
        by_service = defaultdict(list)
        
        # Summary statistics
        total_controls = len(results)
        compliant_controls = 0
        controls_with_violations = 0
        total_violations = 0
        
        # Process each result
        for result in results:
            control = result['control']
            interrogation_result = result['result']
            
            service = control.get('service', 'unknown')
            by_service[service].append(result)
            
            # Count violations
            violations = interrogation_result.get('violations', [])
            if violations:
                controls_with_violations += 1
                total_violations += len(violations)
            else:
                compliant_controls += 1
                
        # Build summary
        summary = {
            'statistics': {
                'total_controls_checked': total_controls,
                'compliant_controls': compliant_controls,
                'controls_with_violations': controls_with_violations,
                'total_violations': total_violations,
                'compliance_percentage': (compliant_controls / total_controls * 100) if total_controls > 0 else 0
            },
            'by_service': {}
        }
        
        # Process by service
        for service, service_results in by_service.items():
            service_violations = []
            service_compliant = 0
            
            for result in service_results:
                if result['result'].get('violations'):
                    service_violations.extend(result['result']['violations'])
                else:
                    service_compliant += 1
                    
            summary['by_service'][service] = {
                'total_controls': len(service_results),
                'compliant': service_compliant,
                'violations': len(service_violations),
                'details': service_results
            }
            
        # Add raw results
        summary['raw_results'] = results
        
        return summary
        
    def format_violation_summary(self, violations: List[Dict[str, Any]]) -> str:
        """
        Format violations for display
        
        Args:
            violations: List of violations
            
        Returns:
            Formatted string
        """
        if not violations:
            return "No violations found"
            
        # Group by offender
        by_offender = defaultdict(list)
        for violation in violations:
            offender = violation.get('offender', 'Unknown')
            by_offender[offender].append(violation)
            
        # Format output
        lines = []
        for offender, offender_violations in by_offender.items():
            lines.append(f"✗ {offender} ({len(offender_violations)} violations)")
            
        return "\n".join(lines)
