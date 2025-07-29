"""
S3 Policy Interrogator
Checks S3 bucket policy configurations
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
import json
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class S3PolicyInterrogator(BaseInterrogator):
    """Interrogator for S3 policy checks"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.s3_client = self.session.client('s3')
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            's3:ListAllMyBuckets',
            's3:GetBucketPolicy',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute S3 policy interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        check_type = params.get('check_type')
        
        if check_type == 'tls_version':
            return self._check_tls_version(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown check type: {check_type}'}
            )
            
    def _check_tls_version(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check S3 bucket TLS version requirements"""
        control_id = control_config['control_id']
        min_version = control_config['interrogation']['parameters'].get('min_version', '1.3')
        violations = []
        
        try:
            # List all buckets
            buckets_response = self.s3_client.list_buckets()
            
            for bucket in buckets_response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket policy
                    policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy = json.loads(policy_response['Policy'])
                    
                    # Check if policy enforces TLS version
                    has_tls_check = False
                    correct_version = False
                    
                    for statement in policy.get('Statement', []):
                        if statement.get('Effect') == 'Deny':
                            condition = statement.get('Condition', {})
                            numeric_less_than = condition.get('NumericLessThan', {})
                            tls_version = numeric_less_than.get('s3:TlsVersion')
                            
                            if tls_version:
                                has_tls_check = True
                                if float(tls_version) >= float(min_version):
                                    correct_version = True
                                    
                    if not has_tls_check:
                        violations.append(ViolationDetail(
                            offender_identity=bucket_name,
                            offender_account=boto3.client('sts').get_caller_identity()['Account'],
                            action_taken='No TLS version requirement in bucket policy',
                            resource_affected=f'arn:aws:s3:::{bucket_name}'
                        ))
                    elif not correct_version:
                        violations.append(ViolationDetail(
                            offender_identity=bucket_name,
                            offender_account=boto3.client('sts').get_caller_identity()['Account'],
                            action_taken=f'TLS version requirement less than {min_version}',
                            resource_affected=f'arn:aws:s3:::{bucket_name}'
                        ))
                        
                except self.s3_client.exceptions.NoSuchBucketPolicy:
                    # No policy = no TLS requirement
                    violations.append(ViolationDetail(
                        offender_identity=bucket_name,
                        offender_account=boto3.client('sts').get_caller_identity()['Account'],
                        action_taken='No bucket policy (no TLS requirement)',
                        resource_affected=f'arn:aws:s3:::{bucket_name}'
                    ))
                except Exception:
                    # Skip buckets we can't access
                    pass
                    
        except Exception as e:
            pass
            
        # Check CloudTrail
        historical = self.check_cloudtrail(control_config, context)
        
        return InterrogationResult(
            control_id=control_id,
            violation_type='current' if violations else 'compliant',
            violations=violations + historical,
            summary={
                'current_violations': len(violations),
                'historical_violations': len(historical)
            }
        )
        
    def _build_cloudtrail_filter(self, control_config: Dict[str, Any]) -> str:
        """Build CloudTrail filter"""
        return '{ $.eventName = PutBucketPolicy || $.eventName = DeleteBucketPolicy }'
        
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event"""
        event_name = event.get('eventName', '')
        offender, account_id, offender_arn = self._extract_user_identity(event)
        
        request_params = event.get('requestParameters', {})
        bucket_name = request_params.get('bucketName', 'Unknown')
        
        return ViolationDetail(
            offender_identity=offender,
            offender_account=account_id,
            offender_arn=offender_arn,
            action_taken=event_name,
            resource_affected=f'arn:aws:s3:::{bucket_name}',
            violation_timestamp=datetime.strptime(event['eventTime'], '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=None),
            source_ip=event.get('sourceIPAddress'),
            access_method=event.get('userAgent', '').split('/')[0] if event.get('userAgent') else None
        )
