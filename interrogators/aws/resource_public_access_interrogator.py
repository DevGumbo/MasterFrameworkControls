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
        check_type = params.get('check_type', 'public_access')
        resource_type = params.get('resource_type')
        
        # Route based on check type
        if check_type == 's3_public_access' or (check_type == 'public_access' and resource_type == 'S3Bucket'):
            return self._check_s3_public_access(control_config, context)
        elif check_type == 'snapshot_public_access' or (check_type == 'public_access' and resource_type == 'EBSSnapshot'):
            return self._check_snapshot_public_access(control_config, context)
        elif check_type == 'rds_public_access' or (check_type == 'public_access' and resource_type == 'RDSInstance'):
            return self._check_rds_public_access(control_config, context)
        elif check_type == 'block_public_access':
            return self._check_s3_block_public_access(control_config, context)
        elif check_type == 'publicly_accessible':
            return self._check_rds_publicly_accessible(control_config, context)
        elif check_type == 'public_sharing':
            return self._check_resource_public_sharing(control_config, context)
        elif check_type == 'ingress_rules':
            return self._check_security_group_ingress(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown check type: {check_type}'}
            )
            
    def _check_s3_block_public_access(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check S3 account-level block public access settings"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            # Check account-level block public access
            response = self.s3_client.get_public_access_block()
            config = response['PublicAccessBlockConfiguration']
            
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                violations.append(ViolationDetail(
                    offender_identity='AWS Account',
                    offender_account=boto3.client('sts').get_caller_identity()['Account'],
                    action_taken='S3 account-level block public access not fully enabled',
                    resource_affected='S3 Block Public Access',
                    violation_timestamp=datetime.utcnow()
                ))
        except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            violations.append(ViolationDetail(
                offender_identity='AWS Account',
                offender_account=boto3.client('sts').get_caller_identity()['Account'],
                action_taken='S3 account-level block public access not configured',
                resource_affected='S3 Block Public Access',
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
        
    def _check_rds_publicly_accessible(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check RDS instances and clusters for public accessibility"""
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
            
        # Check RDS clusters
        try:
            paginator = self.rds_client.get_paginator('describe_db_clusters')
            for page in paginator.paginate():
                for cluster in page.get('DBClusters', []):
                    # Check cluster members
                    for member in cluster.get('DBClusterMembers', []):
                        if member.get('IsClusterWriter'):
                            # Check the writer instance
                            instance_response = self.rds_client.describe_db_instances(
                                DBInstanceIdentifier=member['DBInstanceIdentifier']
                            )
                            for db in instance_response.get('DBInstances', []):
                                if db.get('PubliclyAccessible', False):
                                    violations.append(ViolationDetail(
                                        offender_identity=cluster['DBClusterIdentifier'],
                                        offender_account=cluster['DBClusterArn'].split(':')[4],
                                        action_taken='RDS cluster has publicly accessible instance',
                                        resource_affected=cluster['DBClusterArn'],
                                        violation_timestamp=datetime.utcnow()
                                    ))
                                    break
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
        
    def _check_resource_public_sharing(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check various resources for public sharing"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        # Route based on resource type in title
        if 'documentdb' in title:
            # Check DocumentDB snapshots
            try:
                docdb_client = self.session.client('docdb')
                response = docdb_client.describe_db_cluster_snapshots(
                    SnapshotType='manual'
                )
                for snapshot in response.get('DBClusterSnapshots', []):
                    attrs = docdb_client.describe_db_cluster_snapshot_attributes(
                        DBClusterSnapshotIdentifier=snapshot['DBClusterSnapshotIdentifier']
                    )
                    for attr in attrs.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', []):
                        if attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []):
                            violations.append(ViolationDetail(
                                offender_identity=snapshot['DBClusterSnapshotIdentifier'],
                                offender_account=snapshot['DBClusterSnapshotArn'].split(':')[4],
                                action_taken='DocumentDB snapshot is publicly restorable',
                                resource_affected=snapshot['DBClusterSnapshotArn'],
                                violation_timestamp=datetime.utcnow()
                            ))
            except Exception as e:
                pass
        elif 'rds' in title and 'snapshot' in title:
            # Check RDS snapshots
            try:
                response = self.rds_client.describe_db_snapshots(
                    SnapshotType='manual'
                )
                for snapshot in response.get('DBSnapshots', []):
                    attrs = self.rds_client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier']
                    )
                    for attr in attrs.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                        if attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []):
                            violations.append(ViolationDetail(
                                offender_identity=snapshot['DBSnapshotIdentifier'],
                                offender_account=snapshot['DBSnapshotArn'].split(':')[4],
                                action_taken='RDS snapshot is publicly restorable',
                                resource_affected=snapshot['DBSnapshotArn'],
                                violation_timestamp=datetime.utcnow()
                            ))
            except Exception as e:
                pass
        elif 'ebs' in title or 'ec2' in title:
            # Already handled in snapshot_public_access
            return self._check_snapshot_public_access(control_config, context)
            
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
        
    def _check_security_group_ingress(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check security group ingress rules for public access"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        ports = params.get('ports', [])
        violations = []
        
        try:
            # Get all security groups
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    # Check ingress rules
                    for rule in sg.get('IpPermissions', []):
                        # Check if rule allows access from 0.0.0.0/0 or ::/0
                        public_cidrs = []
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                public_cidrs.append('0.0.0.0/0')
                        for ipv6_range in rule.get('Ipv6Ranges', []):
                            if ipv6_range.get('CidrIpv6') == '::/0':
                                public_cidrs.append('::/0')
                                
                        if public_cidrs:
                            # Check if specific ports are mentioned
                            if ports:
                                for port in ports:
                                    if (rule.get('FromPort', 0) <= port <= rule.get('ToPort', 65535) or
                                        rule.get('IpProtocol') == '-1'):
                                        violations.append(ViolationDetail(
                                            offender_identity=sg['GroupId'],
                                            offender_account=sg['OwnerId'],
                                            action_taken=f'Security group allows public access on port {port}',
                                            resource_affected=f"arn:aws:ec2:{self.aws_config['region']}:{sg['OwnerId']}:security-group/{sg['GroupId']}",
                                            violation_timestamp=datetime.utcnow()
                                        ))
                            else:
                                # General public access check
                                violations.append(ViolationDetail(
                                    offender_identity=sg['GroupId'],
                                    offender_account=sg['OwnerId'],
                                    action_taken=f'Security group allows public access from {public_cidrs[0]}',
                                    resource_affected=f"arn:aws:ec2:{self.aws_config['region']}:{sg['OwnerId']}:security-group/{sg['GroupId']}",
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
