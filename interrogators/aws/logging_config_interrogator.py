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
        check_type = params.get('check_type', '')
        service = params.get('service', '')
        
        # Route based on check type first, then service
        if check_type == 'cloudtrail_logging' or service == 'cloudtrail':
            return self._check_cloudtrail_logging(control_config, context)
        elif check_type == 'vpc_flow_logs' or service == 'vpc_flow_logs':
            return self._check_vpc_flow_logs(control_config, context)
        elif check_type == 'enabled':
            return self._check_logging_enabled(control_config, context)
        elif check_type == 'log_validation':
            return self._check_log_validation(control_config, context)
        elif check_type == 'multi_region':
            return self._check_multi_region(control_config, context)
        elif check_type == 'access_logging':
            return self._check_access_logging(control_config, context)
        elif check_type == 'logging':
            return self._check_general_logging(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='compliant',
                violations=[],
                summary={'message': f'Not implemented for {check_type or service}'}
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
        
    def _check_logging_enabled(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check if logging is enabled for various services"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        # Route based on service in title
        if 'vpc flow' in title:
            return self._check_vpc_flow_logs(control_config, context)
        elif 'cloudtrail' in title:
            return self._check_cloudtrail_logging(control_config, context)
        else:
            # Generic logging check - just check CloudTrail history
            historical = self.check_cloudtrail(control_config, context)
            return InterrogationResult(
                control_id=control_id,
                violation_type='historical' if historical else 'compliant',
                violations=historical,
                summary={'historical_violations': len(historical)}
            )
            
    def _check_log_validation(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check CloudTrail log file validation"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            trails = self.cloudtrail_client.describe_trails()['trailList']
            
            for trail in trails:
                trail_name = trail['Name']
                trail_detail = self.cloudtrail_client.get_trail(Name=trail_name)['Trail']
                
                if not trail_detail.get('LogFileValidationEnabled', False):
                    violations.append(ViolationDetail(
                        offender_identity=trail_name,
                        offender_account=boto3.client('sts').get_caller_identity()['Account'],
                        action_taken='Log file validation not enabled',
                        resource_affected=trail['TrailARN'],
                        violation_timestamp=datetime.utcnow()
                    ))
        except Exception as e:
            pass
            
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
        
    def _check_multi_region(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check for multi-region CloudTrail"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            trails = self.cloudtrail_client.describe_trails()['trailList']
            
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
                    resource_affected='CloudTrail configuration',
                    violation_timestamp=datetime.utcnow()
                ))
        except Exception as e:
            pass
            
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
        
    def _check_access_logging(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check S3 bucket access logging"""
        control_id = control_config['control_id']
        violations = []
        
        s3_client = self.session.client('s3')
        
        try:
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
                    
                    # Check if logging is enabled
                    if 'LoggingEnabled' not in logging_response:
                        violations.append(ViolationDetail(
                            offender_identity=bucket_name,
                            offender_account=boto3.client('sts').get_caller_identity()['Account'],
                            action_taken='S3 bucket access logging not enabled',
                            resource_affected=f'arn:aws:s3:::{bucket_name}',
                            violation_timestamp=datetime.utcnow()
                        ))
                except Exception:
                    # Skip buckets we can't access
                    pass
        except Exception as e:
            pass
            
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
        
    def _check_general_logging(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """General logging check for various services"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        # Route based on service mentioned in title
        if 'elasticsearch' in title or 'opensearch' in title:
            # Check OpenSearch/ES audit logging
            es_client = self.session.client('es')
            try:
                domains = es_client.list_domain_names()['DomainNames']
                for domain in domains:
                    domain_name = domain['DomainName']
                    domain_config = es_client.describe_elasticsearch_domain(DomainName=domain_name)
                    log_options = domain_config['DomainStatus'].get('LogPublishingOptions', {})
                    
                    # Check if audit logs are enabled
                    audit_logs = log_options.get('AUDIT_LOGS', {})
                    if not audit_logs.get('Enabled', False):
                        violations.append(ViolationDetail(
                            offender_identity=domain_name,
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Audit logging not enabled',
                            resource_affected=domain_config['DomainStatus']['ARN'],
                            violation_timestamp=datetime.utcnow()
                        ))
            except Exception:
                pass
        elif 'network firewall' in title:
            # Check Network Firewall logging
            nfw_client = self.session.client('network-firewall')
            try:
                firewalls = nfw_client.list_firewalls()['Firewalls']
                for fw in firewalls:
                    fw_arn = fw['FirewallArn']
                    fw_config = nfw_client.describe_firewall(FirewallArn=fw_arn)
                    
                    # Check logging configuration
                    logging_config = nfw_client.describe_logging_configuration(FirewallArn=fw_arn)
                    log_config = logging_config.get('LoggingConfiguration', {})
                    
                    if not log_config.get('LogDestinationConfigs'):
                        violations.append(ViolationDetail(
                            offender_identity=fw['FirewallName'],
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Logging not configured',
                            resource_affected=fw_arn,
                            violation_timestamp=datetime.utcnow()
                        ))
            except Exception:
                pass
        else:
            # Default - check CloudTrail history
            pass
            
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
