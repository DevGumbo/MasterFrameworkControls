"""
Service Configuration Interrogator
Checks service-specific configurations
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class ServiceConfigInterrogator(BaseInterrogator):
    """Interrogator for service-specific configuration controls"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        # Initialize clients as needed based on control
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            'account:GetAlternateContact',
            'acm:ListCertificates',
            'acm:DescribeCertificate',
            'apigateway:GetRestApis',
            'apigateway:GetStages',
            'autoscaling:DescribeAutoScalingGroups',
            'autoscaling:DescribeLaunchConfigurations',
            'codebuild:BatchGetProjects',
            'cognito-idp:ListUserPools',
            'cognito-idp:DescribeUserPool',
            'dms:DescribeReplicationInstances',
            'documentdb:DescribeDBClusters',
            'dynamodb:ListTables',
            'dynamodb:DescribeTable',
            'ec2:DescribeInstances',
            'ec2:DescribeVpcs',
            'ecs:ListClusters',
            'ecs:DescribeClusters',
            'elasticbeanstalk:DescribeEnvironments',
            'elasticache:DescribeCacheClusters',
            'elasticache:DescribeReplicationGroups',
            'es:ListDomainNames',
            'es:DescribeElasticsearchDomains',
            'iam:GetAccountSummary',
            'inspector2:BatchGetAccountStatus',
            'lambda:ListFunctions',
            'lambda:GetFunction',
            'macie2:GetMacieSession',
            'macie2:GetAutomatedDiscoveryConfiguration',
            'mq:ListBrokers',
            'mq:DescribeBroker',
            'network-firewall:ListFirewalls',
            'network-firewall:DescribeFirewall',
            'rds:DescribeDBInstances',
            'rds:DescribeDBClusters',
            's3:ListBuckets',
            's3:GetBucketVersioning',
            'sns:ListTopics',
            'ssm:DescribeDocuments',
            'ssm:DescribeDocumentPermission',
            'ssm:GetServiceSetting',
            'transfer:ListServers',
            'transfer:DescribeServer',
            'workspaces:DescribeWorkspaces',
            'acm-pca:ListCertificateAuthorities',
            'acm-pca:DescribeCertificateAuthority',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute service configuration interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        check_type = params.get('check_type', 'general')
        
        # Route to appropriate check method
        if check_type == 'general':
            return self._check_general_config(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown check type: {check_type}'}
            )
            
    def _check_general_config(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """General configuration checks for various services"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        
        # Route based on control content
        if 'security contact' in title:
            return self._check_security_contact(control_config, context)
        elif 'iam' in title and 'policies' in title:
            return self._check_iam_policies(control_config, context)
        elif 'certificate' in title:
            return self._check_certificates(control_config, context)
        elif 'api gateway' in title:
            return self._check_api_gateway(control_config, context)
        elif 'auto scaling' in title or 'autoscaling' in title:
            return self._check_autoscaling(control_config, context)
        elif 'cognito' in title:
            return self._check_cognito(control_config, context)
        elif 'dms' in title:
            return self._check_dms(control_config, context)
        elif 'documentdb' in title:
            return self._check_documentdb(control_config, context)
        elif 'dynamodb' in title:
            return self._check_dynamodb(control_config, context)
        elif 'ecs' in title:
            return self._check_ecs(control_config, context)
        elif 'elasticache' in title:
            return self._check_elasticache(control_config, context)
        elif 'elastic beanstalk' in title:
            return self._check_elastic_beanstalk(control_config, context)
        elif 'glue' in title:
            return self._check_glue(control_config, context)
        elif 'inspector' in title:
            return self._check_inspector(control_config, context)
        elif 'lambda' in title:
            return self._check_lambda(control_config, context)
        elif 'macie' in title:
            return self._check_macie(control_config, context)
        elif 'amazon mq' in title or 'mq broker' in title:
            return self._check_mq(control_config, context)
        elif 'network firewall' in title:
            return self._check_network_firewall(control_config, context)
        elif 'private ca' in title or 'certificate authority' in title:
            return self._check_private_ca(control_config, context)
        elif 'rds' in title:
            return self._check_rds(control_config, context)
        elif 's3' in title:
            return self._check_s3(control_config, context)
        elif 'transfer family' in title:
            return self._check_transfer_family(control_config, context)
        elif 'workspaces' in title:
            return self._check_workspaces(control_config, context)
        else:
            # Default implementation - check CloudTrail for changes
            return self._check_cloudtrail_only(control_config, context)
            
    def _check_security_contact(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check if security contact is configured"""
        control_id = control_config['control_id']
        violations = []
        
        try:
            account_client = self.session.client('account')
            response = account_client.get_alternate_contact(AlternateContactType='SECURITY')
            
            if not response.get('AlternateContact'):
                violations.append(ViolationDetail(
                    offender_identity='AWS Account',
                    offender_account=self.aws_config['account_ids'][0],
                    action_taken='Security contact not configured',
                    resource_affected='Account security contact',
                    violation_timestamp=datetime.utcnow()
                ))
        except account_client.exceptions.ResourceNotFoundException:
            violations.append(ViolationDetail(
                offender_identity='AWS Account',
                offender_account=self.aws_config['account_ids'][0],
                action_taken='Security contact not configured',
                resource_affected='Account security contact',
                violation_timestamp=datetime.utcnow()
            ))
        except Exception as e:
            # Account API might not be available in all regions
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
        
    def _check_iam_policies(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check IAM policy configurations"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        iam_client = self.session.client('iam')
        
        # Check for specific policy patterns
        if 'full "*:*"' in title or 'administrative' in title:
            # Check for overly permissive policies
            paginator = iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    # Get policy version
                    try:
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        document = policy_version['PolicyVersion']['Document']
                        if self._is_overly_permissive_policy(document):
                            violations.append(ViolationDetail(
                                offender_identity=policy['PolicyName'],
                                offender_account=self.aws_config['account_ids'][0],
                                action_taken='Policy allows full "*:*" administrative privileges',
                                resource_affected=policy['Arn'],
                                violation_timestamp=datetime.utcnow()
                            ))
                    except:
                        continue
                        
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
        
    def _is_overly_permissive_policy(self, policy_document: Dict) -> bool:
        """Check if policy is overly permissive"""
        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if '*' in actions or '*:*' in actions:
                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    if '*' in resources:
                        return True
        return False
        
    def _check_rds(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check RDS configurations"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        rds_client = self.session.client('rds')
        
        # Route based on specific RDS check
        if 'minor version' in title:
            # Check auto minor version upgrade
            paginator = rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    if not instance.get('AutoMinorVersionUpgrade', False):
                        violations.append(ViolationDetail(
                            offender_identity=instance['DBInstanceIdentifier'],
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Auto minor version upgrade disabled',
                            resource_affected=instance['DBInstanceArn'],
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
        
    def _check_elastic_beanstalk(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check Elastic Beanstalk configurations"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        eb_client = self.session.client('elasticbeanstalk')
        
        try:
            response = eb_client.describe_environments()
            
            for env in response['Environments']:
                if 'enhanced health' in title:
                    # Check health reporting
                    if env.get('Health') == 'Grey' or env.get('HealthStatus') == 'NoData':
                        violations.append(ViolationDetail(
                            offender_identity=env['EnvironmentName'],
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Enhanced health reporting not enabled',
                            resource_affected=env['EnvironmentArn'],
                            violation_timestamp=datetime.utcnow()
                        ))
                elif 'managed platform updates' in title:
                    # Check platform updates
                    config_response = eb_client.describe_configuration_settings(
                        ApplicationName=env['ApplicationName'],
                        EnvironmentName=env['EnvironmentName']
                    )
                    # Check for managed platform updates in config
                    # This would require parsing configuration options
                    pass
        except Exception as e:
            logger.error(f"Error checking Elastic Beanstalk: {e}")
            
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
        
    def _check_macie(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check Macie configurations"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        macie_client = self.session.client('macie2')
        
        try:
            # Check if Macie is enabled
            session_response = macie_client.get_macie_session()
            
            if 'should be enabled' in title:
                if session_response['status'] != 'ENABLED':
                    violations.append(ViolationDetail(
                        offender_identity='Macie',
                        offender_account=self.aws_config['account_ids'][0],
                        action_taken='Macie not enabled',
                        resource_affected='Macie service',
                        violation_timestamp=datetime.utcnow()
                    ))
            elif 'automated sensitive data discovery' in title:
                # Check automated discovery
                auto_response = macie_client.get_automated_discovery_configuration()
                if auto_response['status'] != 'ENABLED':
                    violations.append(ViolationDetail(
                        offender_identity='Macie',
                        offender_account=self.aws_config['account_ids'][0],
                        action_taken='Automated sensitive data discovery not enabled',
                        resource_affected='Macie automated discovery',
                        violation_timestamp=datetime.utcnow()
                    ))
        except macie_client.exceptions.AccessDeniedException:
            # Macie not enabled
            if 'should be enabled' in title:
                violations.append(ViolationDetail(
                    offender_identity='Macie',
                    offender_account=self.aws_config['account_ids'][0],
                    action_taken='Macie not enabled',
                    resource_affected='Macie service',
                    violation_timestamp=datetime.utcnow()
                ))
        except Exception as e:
            logger.error(f"Error checking Macie: {e}")
            
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
        
    def _check_cloudtrail_only(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Default check using only CloudTrail"""
        control_id = control_config['control_id']
        
        # Check CloudTrail for historical violations
        historical = self.check_cloudtrail(control_config, context)
        
        return InterrogationResult(
            control_id=control_id,
            violation_type='historical' if historical else 'compliant',
            violations=historical,
            summary={
                'current_violations': 0,
                'historical_violations': len(historical),
                'note': 'Only CloudTrail history checked for this control'
            }
        )
        
    # Add stub methods for other services
    def _check_certificates(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_api_gateway(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_autoscaling(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_cognito(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_dms(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_documentdb(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_dynamodb(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_ecs(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_elasticache(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_glue(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_inspector(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_lambda(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_mq(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_network_firewall(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_private_ca(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_s3(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_transfer_family(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _check_workspaces(self, control_config, context):
        return self._check_cloudtrail_only(control_config, context)
        
    def _build_cloudtrail_filter(self, control_config: Dict[str, Any]) -> str:
        """Build CloudTrail filter for service config events"""
        title = control_config.get('title', '').lower()
        
        # Build filters based on service
        if 'security contact' in title:
            return '{ $.eventName = PutAlternateContact || $.eventName = DeleteAlternateContact }'
        elif 'iam' in title and 'policies' in title:
            return '{ $.eventName = CreatePolicy || $.eventName = CreatePolicyVersion }'
        elif 'rds' in title:
            return '{ $.eventName = ModifyDBInstance || $.eventName = CreateDBInstance }'
        else:
            # Generic filter for configuration changes
            return '{ $.eventName = Create* || $.eventName = Update* || $.eventName = Modify* }'
            
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event for service config violations"""
        event_name = event.get('eventName', '')
        offender, account_id, offender_arn = self._extract_user_identity(event)
        
        # Only process if from external account
        if account_id in self.org_accounts:
            return None
            
        return ViolationDetail(
            offender_identity=offender,
            offender_account=account_id,
            offender_arn=offender_arn,
            action_taken=event_name,
            resource_affected=event.get('requestParameters', {}).get('resourceArn', 'Service configuration'),
            violation_timestamp=datetime.strptime(event['eventTime'], '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=None),
            source_ip=event.get('sourceIPAddress'),
            access_method=event.get('userAgent', '').split('/')[0] if event.get('userAgent') else None
        )
