# MasterFrameworkControls

This directory contains the modular control framework for AWS security compliance scanning.

## Directory Structure

```
MasterFrameworkControls/
├── control_definitions/       # JSON control definitions
│   ├── aws/                  # AWS service controls
│   └── standards/            # Standards mappings
├── interrogators/            # Python interrogation modules
│   └── aws/                  # AWS-specific interrogators
├── framework/                # Core execution engine
├── config/                   # Configuration files
├── importers/                # Control import utilities
├── reports/                  # Output directory
├── logs/                     # Execution logs
└── tests/                    # Unit tests
```

## Quick Start

1. Import controls: `python import_controls.py`
2. Run analysis: `python run_analysis.py --standard cis_v3`
3. View report: `open reports/latest_report.html`
