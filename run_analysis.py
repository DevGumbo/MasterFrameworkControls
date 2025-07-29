#!/usr/bin/env python3
"""
Main execution script for the control framework
"""

import argparse
import logging
import json
import sys
from datetime import datetime
from pathlib import Path

# Add framework to path
sys.path.append(str(Path(__file__).parent))

from framework.execution_engine import ExecutionEngine
from framework.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='AWS Security Control Framework')
    parser.add_argument('--config', default='config/execution_config.yaml',
                       help='Configuration file path')
    parser.add_argument('--standard', help='Standard to check (e.g., cis_v3_0)')
    parser.add_argument('--services', nargs='+', 
                       help='Services to check (e.g., ec2 s3 iam)')
    parser.add_argument('--controls', nargs='+',
                       help='Specific control IDs to check')
    parser.add_argument('--output', default='reports/latest_report.html',
                       help='Output report file')
    parser.add_argument('--format', choices=['html', 'json', 'console'], 
                       default='console',
                       help='Output format')
    
    args = parser.parse_args()
    
    try:
        # Initialize engine
        logger.info("Initializing execution engine...")
        engine = ExecutionEngine(args.config)
        
        # Execute controls
        logger.info("Executing control checks...")
        results = engine.execute(
            standard=args.standard,
            services=args.services,
            control_ids=args.controls
        )
        
        # Generate output
        if args.format == 'console':
            print_console_report(results)
        elif args.format == 'json':
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"JSON report saved to {args.output}")
        elif args.format == 'html':
            generator = ReportGenerator()
            generator.generate_html_report(results, args.output)
            logger.info(f"HTML report saved to {args.output}")
            
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}", exc_info=True)
        sys.exit(1)


def print_console_report(results: dict):
    """Print results to console"""
    print("\n" + "="*60)
    print("AWS SECURITY CONTROL ANALYSIS REPORT")
    print("="*60)
    print(f"Execution Time: {results['execution_time']}")
    print(f"Controls Executed: {results['controls_executed']}")
    
    stats = results['results']['statistics']
    print(f"\nSUMMARY:")
    print(f"  Compliant Controls: {stats['compliant_controls']}")
    print(f"  Controls with Violations: {stats['controls_with_violations']}")
    print(f"  Total Violations: {stats['total_violations']}")
    print(f"  Compliance Rate: {stats['compliance_percentage']:.1f}%")
    
    print("\nVIOLATIONS BY SERVICE:")
    for service, service_data in results['results']['by_service'].items():
        if service_data['violations'] > 0:
            print(f"\n{service.upper()} ({service_data['violations']} violations):")
            
            for detail in service_data['details']:
                control = detail['control']
                result = detail['result']
                violations = result.get('violations', [])
                
                if violations:
                    print(f"\n  Control: {control['control_id']} - {control['title']}")
                    print(f"  Severity: {control['severity']}")
                    
                    # Group violations by type
                    historical = [v for v in violations if v.get('timestamp')]
                    current = [v for v in violations if not v.get('timestamp')]
                    
                    if historical:
                        print(f"\n    CLOUDTRAIL (Past 30 days):")
                        for v in historical[:5]:  # Show first 5
                            print(f"    ✗ {v['offender']} - {v['action']}")
                        if len(historical) > 5:
                            print(f"    ... and {len(historical) - 5} more")
                            
                    if current:
                        print(f"\n    CURRENT STATE:")
                        for v in current[:5]:  # Show first 5
                            print(f"    ✗ {v['resource']}")
                        if len(current) > 5:
                            print(f"    ... and {len(current) - 5} more")
    
    print("\n" + "="*60)


if __name__ == '__main__':
    main()
