# AWS Security Control Framework - Quick Start Guide

## Overview
This framework provides automated security control checking for AWS environments based on CIS benchmarks and AWS Foundational Security Best Practices.

## Setup

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure AWS Credentials**
   Ensure your AWS credentials are configured:
   ```bash
   aws configure
   ```

3. **Update Configuration**
   Edit `config/execution_config.yaml`:
   - Add your AWS organization account IDs
   - Set your CloudTrail log group name
   - Configure your AWS region

## Usage

### Check All Controls
```bash
python run_analysis.py
```

### Check Specific Standard
```bash
# Check CIS v3.0 controls
python run_analysis.py --standard cis_v3_0

# Check AWS Foundational Security Best Practices
python run_analysis.py --standard fsbp
```

### Check Specific Services
```bash
# Check only IAM and S3 controls
python run_analysis.py --services iam s3
```

### Check Specific Controls
```bash
# Check specific control IDs
python run_analysis.py --controls IAM_001 EC2_001
```

### Output Formats
```bash
# Console output (default)
python run_analysis.py

# JSON output
python run_analysis.py --format json --output report.json

# HTML report
python run_analysis.py --format html --output report.html
```

## Understanding Results

### Console Output
```
SUMMARY:
  Compliant Controls: 15
  Controls with Violations: 3
  Total Violations: 7
  Compliance Rate: 83.3%

VIOLATIONS BY SERVICE:

IAM (3 violations):
  Control: IAM_001 - Ensure IAM password policy requires minimum length
  Severity: MEDIUM
  
    CURRENT STATE:
    ✗ Password policy set to 8 characters
```

### Violation Types

1. **CloudTrail Violations**: Historical API calls that violated the control
   - Shows WHO made the call
   - Shows WHEN it happened
   - Limited to past 30 days (configurable)

2. **Current State Violations**: Resources currently non-compliant
   - Shows WHAT resources are misconfigured
   - Shows current state

## Adding New Controls

1. **Add Control Definition**
   Create or update JSON file in `control_definitions/aws/`:
   ```json
   {
     "control_id": "S3_003",
     "title": "S3 buckets should have versioning enabled",
     "interrogation": {
       "class": "ServiceConfigInterrogator",
       "parameters": {
         "check_type": "versioning_enabled"
       }
     }
   }
   ```

2. **Run Import Script**
   ```bash
   python import_controls.py --csv new_controls.csv
   ```

## Interrogator Patterns

The framework includes 7 base interrogator patterns:

1. **IAMPolicyInterrogator**: Password policies, MFA, access keys
2. **ResourcePublicAccessInterrogator**: Public S3, snapshots, etc.
3. **NetworkSecurityInterrogator**: Security groups, NACLs
4. **EncryptionConfigInterrogator**: At-rest and in-transit encryption
5. **LoggingConfigInterrogator**: Service logging enablement
6. **ServiceConfigInterrogator**: Service-specific settings
7. **ComplianceMonitoringInterrogator**: Config, CloudWatch

## Troubleshooting

### No CloudTrail Access
If you see "Error searching CloudTrail", ensure:
- CloudTrail is enabled
- Your IAM user has `logs:FilterLogEvents` permission
- The log group name in config matches your setup

### Missing Permissions
The framework will work with limited permissions but may skip some checks. See each interrogator's `get_required_permissions()` method for full permission list.

### Performance
- Limit scope with `--services` or `--controls` flags
- Reduce `days_back` in config for faster CloudTrail searches
- Use `--format json` to save results for later analysis

## Architecture

```
Control Definitions (JSON) → Interrogators (Python) → Results
         ↓                           ↓                    ↓
   What to check              How to check it      Violations found
```

The framework:
1. Loads control definitions
2. Maps each to an interrogator class
3. Executes checks (CloudTrail + current state)
4. Reports violations
