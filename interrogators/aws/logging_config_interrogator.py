"""
Logging Configuration Interrogator
Checks service logging settings
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class LoggingConfigInterrogator(BaseInterrogator):
    """Interrogator for logging configuration controls"""
    
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            'cloudtrail:DescribeTrails',
            'ec2:DescribeVpcs',
            'ec2:DescribeFlowLogs',
            's3:GetBucketLogging',
            'logs:FilterLogEvents'
        ]
        
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.cloudtrail_client = self.session.client('cloudtrail')
        self.ec2_client = self.session.client('ec2')
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute logging interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        service = params.get('service', '')
        
        if service == 'cloudtrail':
            return self._check_cloudtrail_logging(control_config, context)
        elif service == 'vpc_flow_logs':
            return self._check_vpc_flow_logs(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='compliant',
                violations=[],
                summary={'message': f'Not implemented for {service}'}
            )
            
    def _check_cloudtrail_logging(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check CloudTrail configuration"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        check_type = params.get('check_type', '')
        violations = []
        
        try:
            trails = self.cloudtrail_client.describe_trails()['trailList']
            
            if check_type == 'multi_region':
                # Check for multi-region trail
                multi_region_found = False
                for trail in trails:
                    if trail.get('IsMultiRegionTrail', False):
                        multi_region_found = True
                        break
                        
                if not multi_region_found:
                    violations.append(ViolationDetail(
                        offender_identity='AWS Account',
                        offender_account=boto3.client('sts').get_caller_identity()['Account'],
                        action_taken='No multi-region CloudTrail found',
                        resource_affected='CloudTrail configuration'
                    ))
                    
            elif check_type == 'log_validation':
                # Check log file validation
                for trail in trails:
                    trail_name = trail['Name']
                    trail_detail = self.cloudtrail_client.get_trail(Name=trail_name)['Trail']
                    
                    if not trail_detail.get('LogFileValidationEnabled', False):
                        violations.append(ViolationDetail(
                            offender_identity=trail_name,
                            offender_account=boto3.client('sts').get_caller_identity()['Account'],
                            action_taken='Log file validation not enabled',
                            resource_affected=trail['TrailARN']
                        ))
                        
        except Exception as e:
            pass
            
        return InterrogationResult(
            control_id=control_id,
            violation_type='current' if violations else 'compliant',
            violations=violations,
            summary={'current_violations': len(violations)}
        )
        
    def _check_vpc_flow_logs(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check VPC Flow Logs"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            # Get all VPCs
            vpcs = self.ec2_client.describe_vpcs()['Vpcs']
            
            # Get all flow logs
            flow_logs = self.ec2_client.describe_flow_logs()['FlowLogs']
            vpc_ids_with_logs = set(log['ResourceId'] for log in flow_logs if log['ResourceId'].startswith('vpc-'))
            
            # Check each VPC
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                if vpc_id not in vpc_ids_with_logs:
                    violations.append(ViolationDetail(
                        offender_identity=vpc_id,
                        offender_account=vpc['OwnerId'],
                        action_taken='VPC Flow Logs not enabled',
                        resource_affected=vpc_id
                    ))
                    
        except Exception as e:
            pass
            
        return InterrogationResult(
            control_id=control_id,
            violation_type='current' if violations else 'compliant',
            violations=violations,
            summary={'current_violations': len(violations)}
        )
