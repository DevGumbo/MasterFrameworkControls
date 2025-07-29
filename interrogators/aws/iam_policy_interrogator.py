"""
IAM Policy Interrogator
Checks IAM-related controls: passwords, MFA, access keys, etc.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import boto3
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from interrogators.base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class IAMPolicyInterrogator(BaseInterrogator):
    """Interrogator for IAM policy-related controls"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.iam_client = self.session.client('iam')
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            'iam:GetAccountPasswordPolicy',
            'iam:ListUsers',
            'iam:ListAccessKeys',
            'iam:GetAccessKeyLastUsed',
            'iam:ListMFADevices',
            'iam:GetLoginProfile',
            'iam:GenerateCredentialReport',
            'iam:GetCredentialReport',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute IAM policy interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        check_type = params.get('check_type')
        
        # Route to appropriate check method
        if check_type == 'password_length':
            return self._check_password_length(control_config, context)
        elif check_type == 'password_reuse':
            return self._check_password_reuse(control_config, context)
        elif check_type == 'password_expiry':
            return self._check_password_expiry(control_config, context)
        elif check_type == 'mfa_enabled':
            return self._check_mfa_enabled(control_config, context)
        elif check_type == 'access_key_rotation':
            return self._check_access_key_rotation(control_config, context)
        elif check_type == 'root_access_keys':
            return self._check_root_access_keys(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown check type: {check_type}'}
            )
            
    def _check_password_length(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check password length requirement"""
        control_id = control_config['control_id']
        min_length = control_config['interrogation']['parameters'].get('min_length', 14)
        violations = []
        
        try:
            # Check current password policy
            response = self.iam_client.get_account_password_policy()
            policy = response['PasswordPolicy']
            
            current_min_length = policy.get('MinimumPasswordLength', 0)
            
            if current_min_length < min_length:
                violations.append(ViolationDetail(
                    offender_identity='AWS Account',
                    offender_account=boto3.client('sts').get_caller_identity()['Account'],
                    action_taken=f'Password policy set to {current_min_length} characters',
                    resource_affected='Account Password Policy',
                    violation_timestamp=datetime.utcnow()
                ))
                
        except self.iam_client.exceptions.NoSuchEntityException:
            # No password policy exists
            violations.append(ViolationDetail(
                offender_identity='AWS Account',
                offender_account=boto3.client('sts').get_caller_identity()['Account'],
                action_taken='No password policy configured',
                resource_affected='Account Password Policy',
                violation_timestamp=datetime.utcnow()
            ))
            
        # Check CloudTrail for who changed the policy
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
        
    def _check_mfa_enabled(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check MFA enabled for users"""
        control_id = control_config['control_id']
        user_type = control_config['interrogation']['parameters'].get('user_type', 'all')
        violations = []
        
        if user_type == 'root':
            # Check root user MFA
            try:
                summary_response = self.iam_client.get_account_summary()
                mfa_enabled = summary_response['SummaryMap'].get('AccountMFAEnabled', 0)
                
                if mfa_enabled == 0:
                    violations.append(ViolationDetail(
                        offender_identity='root',
                        offender_account=boto3.client('sts').get_caller_identity()['Account'],
                        action_taken='MFA not enabled',
                        resource_affected='root user',
                        violation_timestamp=datetime.utcnow()
                    ))
            except Exception as e:
                pass
        else:
            # Check all users with passwords
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    # Check if user has password
                    try:
                        self.iam_client.get_login_profile(UserName=user_name)
                        has_password = True
                    except self.iam_client.exceptions.NoSuchEntityException:
                        has_password = False
                        
                    if has_password:
                        # Check MFA devices
                        mfa_response = self.iam_client.list_mfa_devices(UserName=user_name)
                        if not mfa_response['MFADevices']:
                            violations.append(ViolationDetail(
                                offender_identity=user_name,
                                offender_account=boto3.client('sts').get_caller_identity()['Account'],
                                action_taken='Console access without MFA',
                                resource_affected=f'arn:aws:iam::{boto3.client("sts").get_caller_identity()["Account"]}:user/{user_name}',
                                violation_timestamp=datetime.utcnow()
                            ))
                            
        # Check CloudTrail for historical violations
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
        
    def _check_access_key_rotation(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check access key rotation"""
        control_id = control_config['control_id']
        max_days = control_config['interrogation']['parameters'].get('max_days', 90)
        violations = []
        
        # Check all users' access keys
        paginator = self.iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                
                # List access keys
                keys_response = self.iam_client.list_access_keys(UserName=user_name)
                for key_metadata in keys_response['AccessKeyMetadata']:
                    key_id = key_metadata['AccessKeyId']
                    create_date = key_metadata['CreateDate']
                    
                    # Calculate age
                    key_age = (datetime.utcnow() - create_date.replace(tzinfo=None)).days
                    
                    if key_age > max_days:
                        violations.append(ViolationDetail(
                            offender_identity=user_name,
                            offender_account=boto3.client('sts').get_caller_identity()['Account'],
                            action_taken=f'Access key {key_id} not rotated for {key_age} days',
                            resource_affected=f'arn:aws:iam::{boto3.client("sts").get_caller_identity()["Account"]}:user/{user_name}',
                            violation_timestamp=datetime.utcnow()
                        ))
                        
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
        
    def _check_root_access_keys(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check for root access keys"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            # Check root access keys
            summary_response = self.iam_client.get_account_summary()
            access_keys = summary_response['SummaryMap'].get('AccountAccessKeysPresent', 0)
            
            if access_keys > 0:
                violations.append(ViolationDetail(
                    offender_identity='root',
                    offender_account=boto3.client('sts').get_caller_identity()['Account'],
                    action_taken='Root access keys exist',
                    resource_affected='root user',
                    violation_timestamp=datetime.utcnow()
                ))
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
        
    def _check_password_reuse(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check password reuse prevention"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            # Check current password policy
            response = self.iam_client.get_account_password_policy()
            policy = response['PasswordPolicy']
            
            reuse_prevention = policy.get('PasswordReusePrevention', 0)
            
            if reuse_prevention == 0:
                violations.append(ViolationDetail(
                    offender_identity='AWS Account',
                    offender_account=boto3.client('sts').get_caller_identity()['Account'],
                    action_taken='Password reuse not prevented',
                    resource_affected='Account Password Policy',
                    violation_timestamp=datetime.utcnow()
                ))
                
        except self.iam_client.exceptions.NoSuchEntityException:
            violations.append(ViolationDetail(
                offender_identity='AWS Account',
                offender_account=boto3.client('sts').get_caller_identity()['Account'],
                action_taken='No password policy configured',
                resource_affected='Account Password Policy',
                violation_timestamp=datetime.utcnow()
            ))
            
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
        
    def _check_password_expiry(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check password expiry settings"""
        control_id = control_config['control_id']
        max_days = control_config['interrogation']['parameters'].get('max_days', 90)
        violations = []
        
        try:
            response = self.iam_client.get_account_password_policy()
            policy = response['PasswordPolicy']
            
            max_age = policy.get('MaxPasswordAge', 0)
            
            if max_age == 0 or max_age > max_days:
                violations.append(ViolationDetail(
                    offender_identity='AWS Account',
                    offender_account=boto3.client('sts').get_caller_identity()['Account'],
                    action_taken=f'Password expiry set to {max_age} days' if max_age > 0 else 'Password expiry disabled',
                    resource_affected='Account Password Policy',
                    violation_timestamp=datetime.utcnow()
                ))
                
        except self.iam_client.exceptions.NoSuchEntityException:
            violations.append(ViolationDetail(
                offender_identity='AWS Account',
                offender_account=boto3.client('sts').get_caller_identity()['Account'],
                action_taken='No password policy configured',
                resource_affected='Account Password Policy',
                violation_timestamp=datetime.utcnow()
            ))
            
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
        """Build CloudTrail filter for IAM events"""
        check_type = control_config['interrogation']['parameters'].get('check_type')
        
        if check_type in ['password_length', 'password_reuse', 'password_expiry']:
            return '{ $.eventName = UpdateAccountPasswordPolicy || $.eventName = DeleteAccountPasswordPolicy }'
        elif check_type == 'mfa_enabled':
            return '{ $.eventName = EnableMFADevice || $.eventName = DeactivateMFADevice || $.eventName = DeleteVirtualMFADevice }'
        elif check_type == 'access_key_rotation':
            return '{ $.eventName = CreateAccessKey }'
        elif check_type == 'root_access_keys':
            return '{ $.eventName = CreateAccessKey && $.userIdentity.type = Root }'
        else:
            return ''
            
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event for IAM violations"""
        event_name = event.get('eventName', '')
        
        # Extract user identity
        offender, account_id, offender_arn = self._extract_user_identity(event)
        
        # Only process if from external account (not in org)
        if account_id in self.org_accounts:
            return None
            
        return ViolationDetail(
            offender_identity=offender,
            offender_account=account_id,
            offender_arn=offender_arn,
            action_taken=event_name,
            resource_affected=event.get('requestParameters', {}).get('policyDocument', 'IAM Policy'),
            violation_timestamp=datetime.strptime(event['eventTime'], '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=None),
            source_ip=event.get('sourceIPAddress'),
            access_method=event.get('userAgent', '').split('/')[0] if event.get('userAgent') else None
        )
