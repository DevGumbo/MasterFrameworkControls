"""
Encryption Configuration Interrogator
Checks encryption at-rest and in-transit settings
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class EncryptionConfigInterrogator(BaseInterrogator):
    """Interrogator for encryption configuration controls"""
    
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            's3:GetBucketEncryption',
            'ec2:DescribeVolumes',
            'rds:DescribeDBInstances',
            'logs:FilterLogEvents'
        ]
        
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.s3_client = self.session.client('s3')
        self.ec2_client = self.session.client('ec2')
        self.rds_client = self.session.client('rds')
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute encryption interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        resource_type = params.get('resource_type', '')
        
        if resource_type == 'S3Bucket':
            return self._check_s3_encryption(control_config, context)
        elif resource_type == 'EBS':
            return self._check_ebs_encryption(control_config, context)
        elif resource_type == 'RDS':
            return self._check_rds_encryption(control_config, context)
        else:
            # Return placeholder for now
            return InterrogationResult(
                control_id=control_id,
                violation_type='compliant',
                violations=[],
                summary={'message': f'Not implemented for {resource_type}'}
            )
            
    def _check_ebs_encryption(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check EBS encryption settings"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            # Check if EBS encryption by default is enabled
            response = self.ec2_client.get_ebs_encryption_by_default()
            
            if not response.get('EbsEncryptionByDefault', False):
                violations.append(ViolationDetail(
                    offender_identity='AWS Account',
                    offender_account=boto3.client('sts').get_caller_identity()['Account'],
                    action_taken='EBS encryption by default is disabled',
                    resource_affected='Account-level EBS setting'
                ))
                
        except Exception as e:
            pass
            
        return InterrogationResult(
            control_id=control_id,
            violation_type='current' if violations else 'compliant',
            violations=violations,
            summary={'current_violations': len(violations)}
        )
        
    def _check_s3_encryption(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check S3 bucket encryption"""
        # Placeholder - implement S3 encryption checks
        return InterrogationResult(
            control_id=control_config['control_id'],
            violation_type='compliant',
            violations=[],
            summary={'message': 'S3 encryption check not implemented'}
        )
        
    def _check_rds_encryption(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check RDS encryption"""
        # Placeholder - implement RDS encryption checks
        return InterrogationResult(
            control_id=control_config['control_id'],
            violation_type='compliant',
            violations=[],
            summary={'message': 'RDS encryption check not implemented'}
        )
