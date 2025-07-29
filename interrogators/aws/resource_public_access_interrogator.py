"""
Resource Public Access Interrogator
Checks for resources exposed to public/internet access
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class ResourcePublicAccessInterrogator(BaseInterrogator):
    """Interrogator for public access controls"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.s3_client = self.session.client('s3')
        self.ec2_client = self.session.client('ec2')
        self.rds_client = self.session.client('rds')
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            's3:GetBucketPublicAccessBlock',
            's3:GetBucketPolicyStatus',
            's3:ListAllMyBuckets',
            'ec2:DescribeSnapshots',
            'rds:DescribeDBInstances',
            'rds:DescribeDBClusters',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute public access interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        resource_type = params.get('resource_type')
        
        if resource_type == 'S3Bucket':
            return self._check_s3_public_access(control_config, context)
        elif resource_type == 'EBSSnapshot':
            return self._check_snapshot_public_access(control_config, context)
        elif resource_type == 'RDSInstance':
            return self._check_rds_public_access(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown resource type: {resource_type}'}
            )
            
    def _check_s3_public_access(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check S3 bucket public access"""
        control_id = control_config['control_id']
        violations = []
        
        # List all buckets
        try:
            buckets_response = self.s3_client.list_buckets()
            
            for bucket in buckets_response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Check public access block
                    pab_response = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    pab_config = pab_response['PublicAccessBlockConfiguration']
                    
                    # Check if all settings are enabled
                    if not all([
                        pab_config.get('BlockPublicAcls', False),
                        pab_config.get('IgnorePublicAcls', False),
                        pab_config.get('BlockPublicPolicy', False),
                        pab_config.get('RestrictPublicBuckets', False)
                    ]):
                        violations.append(ViolationDetail(
                            offender_identity=bucket_name,
                            offender_account=boto3.client('sts').get_caller_identity()['Account'],
                            action_taken='Public access not fully blocked',
                            resource_affected=f'arn:aws:s3:::{bucket_name}',
                            violation_timestamp=datetime.utcnow()
                        ))
                        
                except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    # No public access block configured
                    violations.append(ViolationDetail(
                        offender_identity=bucket_name,
                        offender_account=boto3.client('sts').get_caller_identity()['Account'],
                        action_taken='No public access block configured',
                        resource_affected=f'arn:aws:s3:::{bucket_name}',
                        violation_timestamp=datetime.utcnow()
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
        
    def _check_rds_public_access(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check RDS instance public access"""
        control_id = control_config['control_id']
        violations = []
        
        # Check RDS instances
        try:
            paginator = self.rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    if db.get('PubliclyAccessible', False):
                        violations.append(ViolationDetail(
                            offender_identity=db['DBInstanceIdentifier'],
                            offender_account=db['DBInstanceArn'].split(':')[4],
                            action_taken='RDS instance is publicly accessible',
                            resource_affected=db['DBInstanceArn'],
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
        
    def _check_snapshot_public_access(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check EBS snapshot public access"""
        control_id = control_config['control_id']
        violations = []
        
        # Check snapshots
        try:
            response = self.ec2_client.describe_snapshots(OwnerIds=['self'])
            
            for snapshot in response.get('Snapshots', []):
                snapshot_id = snapshot['SnapshotId']
                
                # Check if snapshot is public
                attrs_response = self.ec2_client.describe_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute='createVolumePermission'
                )
                
                for permission in attrs_response.get('CreateVolumePermissions', []):
                    if permission.get('Group') == 'all':
                        violations.append(ViolationDetail(
                            offender_identity=snapshot_id,
                            offender_account=snapshot['OwnerId'],
                            action_taken='Snapshot is publicly restorable',
                            resource_affected=snapshot_id,
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
        
    def _build_cloudtrail_filter(self, control_config: Dict[str, Any]) -> str:
        """Build CloudTrail filter"""
        resource_type = control_config['interrogation']['parameters'].get('resource_type')
        
        if resource_type == 'S3Bucket':
            return '{ $.eventName = PutBucketPublicAccessBlock || $.eventName = DeleteBucketPublicAccessBlock }'
        elif resource_type == 'EBSSnapshot':
            return '{ $.eventName = ModifySnapshotAttribute }'
        elif resource_type == 'RDSInstance':
            return '{ $.eventName = ModifyDBInstance || $.eventName = CreateDBInstance }'
        else:
            return ''
            
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event"""
        event_name = event.get('eventName', '')
        offender, account_id, offender_arn = self._extract_user_identity(event)
        
        request_params = event.get('requestParameters', {})
        resource_id = request_params.get('bucketName', request_params.get('snapshotId', 'Unknown'))
        
        return ViolationDetail(
            offender_identity=offender,
            offender_account=account_id,
            offender_arn=offender_arn,
            action_taken=event_name,
            resource_affected=resource_id,
            violation_timestamp=datetime.strptime(event['eventTime'], '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=None),
            source_ip=event.get('sourceIPAddress'),
            access_method=event.get('userAgent', '').split('/')[0] if event.get('userAgent') else None
        )
