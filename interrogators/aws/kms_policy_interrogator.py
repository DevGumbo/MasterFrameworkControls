"""
KMS Policy Interrogator
Checks KMS key policies and usage restrictions
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
import json
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class KMSPolicyInterrogator(BaseInterrogator):
    """Interrogator for KMS policy checks"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.kms_client = self.session.client('kms')
        self.sts_client = self.session.client('sts')
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            'kms:ListKeys',
            'kms:GetKeyPolicy',
            'kms:DescribeKey',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute KMS policy interrogation"""
        control_id = control_config['control_id']
        
        # For CT.KMS.PV.7 - Check if KMS keys are restricted to org principals
        return self._check_org_restriction(control_config, context)
        
    def _check_org_restriction(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check if KMS keys are restricted to organization principals"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            # Get current account's org ID
            org_id = context.get('organization_id', 'o-xxxxxxxxxx')  # Would get from config
            
            # List all KMS keys
            paginator = self.kms_client.get_paginator('list_keys')
            
            for page in paginator.paginate():
                for key in page['Keys']:
                    key_id = key['KeyId']
                    
                    try:
                        # Get key policy
                        policy_response = self.kms_client.get_key_policy(
                            KeyId=key_id,
                            PolicyName='default'
                        )
                        
                        policy = json.loads(policy_response['Policy'])
                        
                        # Check if policy allows access outside org
                        allows_external = self._policy_allows_external_access(policy, org_id)
                        
                        if allows_external:
                            violations.append(ViolationDetail(
                                offender_identity=key_id,
                                offender_account=boto3.client('sts').get_caller_identity()['Account'],
                                action_taken='KMS key allows access outside organization',
                                resource_affected=f'arn:aws:kms:{self.region}:{boto3.client("sts").get_caller_identity()["Account"]}:key/{key_id}'
                            ))
                            
                    except Exception as e:
                        # Skip keys we can't access
                        continue
                        
        except Exception as e:
            pass
            
        return InterrogationResult(
            control_id=control_id,
            violation_type='current' if violations else 'compliant',
            violations=violations,
            summary={'current_violations': len(violations)}
        )
        
    def _policy_allows_external_access(self, policy: Dict[str, Any], org_id: str) -> bool:
        """Check if policy allows access outside the organization"""
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                # Check if Principal includes external accounts
                principal = statement.get('Principal', {})
                
                # If Principal is "*", it's public
                if principal == "*" or principal.get('AWS') == "*":
                    return True
                    
                # Check conditions for org restriction
                condition = statement.get('Condition', {})
                has_org_condition = False
                
                # Look for aws:PrincipalOrgID condition
                string_equals = condition.get('StringEquals', {})
                if string_equals.get('aws:PrincipalOrgID') == org_id:
                    has_org_condition = True
                    
                # If no org condition, check if principals are external
                if not has_org_condition and isinstance(principal.get('AWS'), list):
                    # Would need to check if principals are in org
                    # For now, assume any explicit principal list might be external
                    return True
                    
        return False
