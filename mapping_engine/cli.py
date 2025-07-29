#!/usr/bin/env python3
"""
Mapping Engine CLI
Main interface for control analysis and mapping
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from mapping_engine.processors.csv_processor_v2 import CSVProcessorV2
from mapping_engine.analyzers.control_deduplicator import ControlDeduplicator
from mapping_engine.mappers.interrogator_mapper import InterrogatorMapper
from mapping_engine.validators.coverage_validator import CoverageValidator


class MappingEngineCLI:
    """Command line interface for mapping engine"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.csv_dir = self.base_dir.parent / 'cloud_control_framework' / 'SecPolicies'
        self.control_dir = self.base_dir / 'control_definitions' / 'aws'
        self.interrogator_dir = self.base_dir / 'interrogators' / 'aws'
        self.output_dir = self.base_dir / 'mapping_engine' / 'output'
        
    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description='Control Mapping Engine - Intelligent control analysis and mapping'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Process CSVs command
        process_parser = subparsers.add_parser('process', help='Process CSV files with enhanced logic')
        process_parser.add_argument('--csv-dir', help='Directory containing CSV files', 
                                  default=str(self.csv_dir))
        process_parser.add_argument('--output-dir', help='Output directory for control JSONs',
                                  default=str(self.control_dir))
        
        # Analyze duplicates command
        dedup_parser = subparsers.add_parser('dedup', help='Analyze control duplicates')
        dedup_parser.add_argument('--control-dir', help='Directory containing control JSONs',
                                default=str(self.control_dir))
        
        # Map interrogators command
        map_parser = subparsers.add_parser('map', help='Map controls to interrogators')
        map_parser.add_argument('--control-dir', help='Directory containing control JSONs',
                              default=str(self.control_dir))
        map_parser.add_argument('--interrogator-dir', help='Directory containing interrogators',
                              default=str(self.interrogator_dir))
        map_parser.add_argument('--fix', action='store_true', help='Generate corrected control files')
        
        # Validate coverage command
        validate_parser = subparsers.add_parser('validate', help='Validate control coverage')
        validate_parser.add_argument('--control-dir', help='Directory containing control JSONs',
                                   default=str(self.control_dir))
        validate_parser.add_argument('--interrogator-dir', help='Directory containing interrogators',
                                   default=str(self.interrogator_dir))
        
        # Full analysis command
        analyze_parser = subparsers.add_parser('analyze', help='Run full analysis pipeline')
        analyze_parser.add_argument('--fix', action='store_true', help='Apply fixes automatically')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
            
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Execute command
        if args.command == 'process':
            self.process_csvs(args)
        elif args.command == 'dedup':
            self.analyze_duplicates(args)
        elif args.command == 'map':
            self.map_interrogators(args)
        elif args.command == 'validate':
            self.validate_coverage(args)
        elif args.command == 'analyze':
            self.full_analysis(args)
            
    def process_csvs(self, args):
        """Process CSV files with enhanced logic"""
        print("Processing CSV files with enhanced logic...")
        
        processor = CSVProcessorV2()
        
        # Find CSV files
        csv_files = {}
        csv_path = Path(args.csv_dir)
        
        for csv_file in csv_path.glob("*.csv"):
            # Extract standard name from filename
            if 'cis_v1_2' in csv_file.name:
                csv_files['cis_v1_2'] = str(csv_file)
            elif 'cis_v1_4' in csv_file.name:
                csv_files['cis_v1_4'] = str(csv_file)
            elif 'cis_v3_0' in csv_file.name:
                csv_files['cis_v3_0'] = str(csv_file)
            elif 'fsbp' in csv_file.name:
                csv_files['fsbp'] = str(csv_file)
                
        if not csv_files:
            print(f"No CSV files found in {args.csv_dir}")
            return
            
        # Process files
        stats = processor.process_csv_files(csv_files)
        
        print(f"\nProcessing complete:")
        print(f"- Total controls: {stats['total_controls']}")
        print(f"- Unique controls: {stats['unique_controls']}")
        print(f"- Duplicates merged: {stats['duplicates_found']}")
        print(f"- Services found: {len(stats['services_found'])}")
        
        # Save output
        output_path = Path(args.output_dir) / 'enhanced'
        processor.save_control_definitions(str(output_path))
        
        # Save processing report
        report_file = self.output_dir / 'processing_report.json'
        with open(report_file, 'w') as f:
            # Convert sets to lists for JSON serialization
            stats_serializable = stats.copy()
            if 'services_found' in stats_serializable and isinstance(stats_serializable['services_found'], set):
                stats_serializable['services_found'] = list(stats_serializable['services_found'])
            
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'stats': stats_serializable,
                'csv_files': csv_files,
                'output_directory': str(output_path)
            }, f, indent=2)
            
        print(f"\nReport saved to: {report_file}")
        
    def analyze_duplicates(self, args):
        """Analyze control duplicates"""
        print("Analyzing control duplicates...")
        
        deduplicator = ControlDeduplicator(args.control_dir)
        report = deduplicator.analyze_duplicates()
        
        print(f"\nDuplication Analysis:")
        print(f"- Total controls: {report['summary']['total_controls']}")
        print(f"- Duplicate groups: {report['summary']['duplicate_groups']}")
        print(f"- Conflicts found: {report['summary']['conflicts_found']}")
        
        # Show sample duplicates
        if report['duplicate_groups']:
            print("\nSample duplicate groups:")
            for group in report['duplicate_groups'][:3]:
                print(f"\n  Group:")
                for control in group['controls']:
                    print(f"    - {control['control_id']}: {control['title'][:60]}...")
                    
        # Save report
        report_file = self.output_dir / 'deduplication_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\nFull report saved to: {report_file}")
        
        # Show consolidation suggestions
        consolidations = deduplicator.suggest_consolidations()
        if consolidations:
            print("\nSuggested consolidations:")
            for method, controls in list(consolidations.items())[:5]:
                print(f"  {method}: {len(controls)} controls")
                
    def map_interrogators(self, args):
        """Map controls to interrogators"""
        print("Mapping controls to interrogators...")
        
        mapper = InterrogatorMapper(args.control_dir, args.interrogator_dir)
        report = mapper.analyze_and_map()
        
        print(f"\nMapping Results:")
        print(f"- Mapped controls: {report['summary']['mapped_controls']}")
        print(f"- Remapped controls: {report['summary']['remapped_controls']}")
        print(f"- Unmapped controls: {report['summary']['unmapped_controls']}")
        print(f"- Interrogators needing methods: {report['summary']['interrogators_needing_methods']}")
        
        # Show available interrogators
        print("\nAvailable interrogators:")
        for name, info in report['available_interrogators'].items():
            print(f"  {name}: {info['method_count']} methods, {len(info['check_types'])} check types")
            
        # Save report
        report_file = self.output_dir / 'mapping_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\nFull report saved to: {report_file}")
        
        # Generate corrected files if requested
        if args.fix and report['remapped_controls']:
            print("\nGenerating corrected control files...")
            output_path = self.control_dir.parent / 'aws_corrected'
            mapper.generate_corrected_controls(report, str(output_path))
            
    def validate_coverage(self, args):
        """Validate control coverage"""
        print("Validating control coverage...")
        
        validator = CoverageValidator(args.control_dir, args.interrogator_dir)
        report = validator.validate_coverage()
        
        print(f"\nValidation Results:")
        print(f"- Total controls: {report['summary']['total_controls']}")
        print(f"- Valid controls: {report['summary']['valid_controls']}")
        print(f"- Invalid controls: {report['summary']['invalid_controls']}")
        print(f"- Coverage: {report['summary']['coverage_percentage']}%")
        
        # Show issues by reason
        if report['invalid_by_reason']:
            print("\nIssues by reason:")
            for reason, controls in report['invalid_by_reason'].items():
                print(f"  {reason}: {len(controls)} controls")
                
        # Show missing interrogators
        if report['missing_interrogators']:
            print("\nMissing interrogators:")
            for interrogator in report['missing_interrogators']:
                print(f"  - {interrogator}")
                
        # Save report
        report_file = self.output_dir / 'coverage_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\nFull report saved to: {report_file}")
        
        # Generate fix script if needed
        if report['invalid_controls']:
            fix_file = self.output_dir / 'coverage_fixes.py'
            validator.generate_fix_script(report, str(fix_file))
            print(f"Fix suggestions saved to: {fix_file}")
            
    def full_analysis(self, args):
        """Run full analysis pipeline"""
        print("Running full analysis pipeline...\n")
        
        # Step 1: Process CSVs
        print("="*60)
        print("Step 1: Processing CSV files")
        print("="*60)
        process_args = argparse.Namespace(
            csv_dir=str(self.csv_dir),
            output_dir=str(self.control_dir)
        )
        self.process_csvs(process_args)
        
        # Step 2: Analyze duplicates
        print("\n" + "="*60)
        print("Step 2: Analyzing duplicates")
        print("="*60)
        dedup_args = argparse.Namespace(control_dir=str(self.control_dir))
        self.analyze_duplicates(dedup_args)
        
        # Step 3: Map interrogators
        print("\n" + "="*60)
        print("Step 3: Mapping interrogators")
        print("="*60)
        map_args = argparse.Namespace(
            control_dir=str(self.control_dir),
            interrogator_dir=str(self.interrogator_dir),
            fix=args.fix
        )
        self.map_interrogators(map_args)
        
        # Step 4: Validate coverage
        print("\n" + "="*60)
        print("Step 4: Validating coverage")
        print("="*60)
        validate_args = argparse.Namespace(
            control_dir=str(self.control_dir),
            interrogator_dir=str(self.interrogator_dir)
        )
        self.validate_coverage(validate_args)
        
        # Summary
        print("\n" + "="*60)
        print("Analysis Complete!")
        print("="*60)
        print(f"All reports saved to: {self.output_dir}")
        
        # Create summary report
        summary = {
            'timestamp': datetime.now().isoformat(),
            'pipeline_steps': [
                'CSV Processing',
                'Duplicate Analysis',
                'Interrogator Mapping',
                'Coverage Validation'
            ],
            'output_directory': str(self.output_dir),
            'fixes_applied': args.fix
        }
        
        summary_file = self.output_dir / 'analysis_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        print(f"\nSummary saved to: {summary_file}")


if __name__ == "__main__":
    cli = MappingEngineCLI()
    cli.run()
