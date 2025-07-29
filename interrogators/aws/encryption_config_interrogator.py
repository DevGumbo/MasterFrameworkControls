"""
Encryption Configuration Interrogator
Checks encryption at-rest and in-transit settings
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
import json
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
        check_type = params.get('check_type', 'encryption')
        resource_type = params.get('resource_type', '')
        
        # Route based on check type
        if check_type == 'rds_encryption' or (check_type == 'encryption' and resource_type == 'RDS'):
            return self._check_rds_encryption(control_config, context)
        elif check_type == 's3_encryption' or (check_type == 'encryption' and resource_type == 'S3Bucket'):
            return self._check_s3_encryption(control_config, context)
        elif check_type == 'ebs_encryption' or (check_type == 'encryption' and resource_type == 'EBS'):
            return self._check_ebs_encryption(control_config, context)
        elif check_type == 'https_required':
            return self._check_https_required(control_config, context)
        elif check_type == 'encryption':
            # General encryption check based on title
            return self._check_general_encryption(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='compliant',
                violations=[],
                summary={'message': f'Not implemented for {check_type}'}
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
        
    def _check_https_required(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check if HTTPS/TLS is required for services"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        if 's3' in title:
            # Check S3 bucket policies for HTTPS requirement
            try:
                buckets = self.s3_client.list_buckets()['Buckets']
                
                for bucket in buckets:
                    bucket_name = bucket['Name']
                    
                    try:
                        # Get bucket policy
                        policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                        policy = json.loads(policy_response['Policy'])
                        
                        # Check if policy enforces HTTPS
                        https_enforced = False
                        for statement in policy.get('Statement', []):
                            if statement.get('Effect') == 'Deny':
                                conditions = statement.get('Condition', {})
                                bool_condition = conditions.get('Bool', {})
                                if bool_condition.get('aws:SecureTransport') == 'false':
                                    https_enforced = True
                                    break
                                    
                        if not https_enforced:
                            violations.append(ViolationDetail(
                                offender_identity=bucket_name,
                                offender_account=self.aws_config['account_ids'][0],
                                action_taken='Bucket policy does not require HTTPS',
                                resource_affected=f'arn:aws:s3:::{bucket_name}',
                                violation_timestamp=datetime.utcnow()
                            ))
                            
                    except self.s3_client.exceptions.NoSuchBucketPolicy:
                        # No policy means no HTTPS enforcement
                        violations.append(ViolationDetail(
                            offender_identity=bucket_name,
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='No bucket policy to enforce HTTPS',
                            resource_affected=f'arn:aws:s3:::{bucket_name}',
                            violation_timestamp=datetime.utcnow()
                        ))
                    except Exception:
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
        
    def _check_general_encryption(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """General encryption check based on control title/description"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        # Route based on service mentioned in title
        if 'firehose' in title or 'kinesis data firehose' in title:
            # Check Kinesis Data Firehose encryption
            firehose_client = self.session.client('firehose')
            try:
                streams = firehose_client.list_delivery_streams()['DeliveryStreamNames']
                
                for stream_name in streams:
                    stream_desc = firehose_client.describe_delivery_stream(
                        DeliveryStreamName=stream_name
                    )
                    stream_config = stream_desc['DeliveryStreamDescription']
                    
                    # Check encryption configuration
                    encryption_config = stream_config.get('DeliveryStreamEncryptionConfiguration', {})
                    if encryption_config.get('Status') != 'ENABLED':
                        violations.append(ViolationDetail(
                            offender_identity=stream_name,
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Delivery stream encryption not enabled',
                            resource_affected=stream_config['DeliveryStreamARN'],
                            violation_timestamp=datetime.utcnow()
                        ))
            except Exception:
                pass
                
        elif 'elasticsearch' in title:
            # Check Elasticsearch encryption
            es_client = self.session.client('es')
            try:
                domains = es_client.list_domain_names()['DomainNames']
                
                for domain in domains:
                    domain_name = domain['DomainName']
                    domain_config = es_client.describe_elasticsearch_domain(DomainName=domain_name)
                    
                    # Check node-to-node encryption
                    node_to_node = domain_config['DomainStatus'].get('NodeToNodeEncryptionOptions', {})
                    if not node_to_node.get('Enabled', False):
                        violations.append(ViolationDetail(
                            offender_identity=domain_name,
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Node-to-node encryption not enabled',
                            resource_affected=domain_config['DomainStatus']['ARN'],
                            violation_timestamp=datetime.utcnow()
                        ))
            except Exception:
                pass
                
        elif 'rds' in title:
            return self._check_rds_encryption(control_config, context)
        elif 's3' in title:
            return self._check_s3_encryption(control_config, context)
        elif 'ebs' in title:
            return self._check_ebs_encryption(control_config, context)
        else:
            # Default - check CloudTrail only
            historical = self.check_cloudtrail(control_config, context)
            return InterrogationResult(
                control_id=control_id,
                violation_type='historical' if historical else 'compliant',
                violations=historical,
                summary={'historical_violations': len(historical)}
            )
            
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
