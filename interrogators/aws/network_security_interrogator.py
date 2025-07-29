"""
Network Security Interrogator
Checks network-related controls: security groups, NACLs, VPC configurations
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult


class NetworkSecurityInterrogator(BaseInterrogator):
    """Interrogator for network security controls"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.ec2_client = self.session.client('ec2')
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            'ec2:DescribeSecurityGroups',
            'ec2:DescribeNetworkAcls',
            'ec2:DescribeVpcs',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute network security interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        check_type = params.get('check_type')
        
        # Route to appropriate check method
        if check_type == 'ingress_rules':
            return self._check_security_group_ingress(control_config, context)
        elif check_type == 'default_sg_rules':
            return self._check_default_security_groups(control_config, context)
        elif check_type == 'nacl_rules':
            return self._check_nacl_rules(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown check type: {check_type}'}
            )
            
    def _check_security_group_ingress(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check security group ingress rules"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        ports = params.get('ports', [])
        source_cidr = params.get('source_cidr', '0.0.0.0/0')
        violations = []
        
        # Get all security groups
        paginator = self.ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'unnamed')
                
                # Check ingress rules
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    # Check if rule includes our ports
                    for port in ports:
                        if from_port <= port <= to_port:
                            # Check if rule allows from 0.0.0.0/0
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == source_cidr:
                                    violations.append(ViolationDetail(
                                        offender_identity=sg_name,
                                        offender_account=sg['OwnerId'],
                                        action_taken=f'Security group allows {source_cidr} to port {port}',
                                        resource_affected=sg_id,
                                        violation_timestamp=datetime.utcnow()
                                    ))
                                    
                            # Also check IPv6
                            for ip_range in rule.get('Ipv6Ranges', []):
                                if ip_range.get('CidrIpv6') == '::/0':
                                    violations.append(ViolationDetail(
                                        offender_identity=sg_name,
                                        offender_account=sg['OwnerId'],
                                        action_taken=f'Security group allows ::/0 to port {port}',
                                        resource_affected=sg_id,
                                        violation_timestamp=datetime.utcnow()
                                    ))
                                    
        # Check CloudTrail for who created/modified these rules
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
        
    def _check_default_security_groups(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check default security group configurations"""
        control_id = control_config['control_id']
        violations = []
        
        # Get all default security groups
        response = self.ec2_client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': ['default']
                }
            ]
        )
        
        for sg in response['SecurityGroups']:
            sg_id = sg['GroupId']
            vpc_id = sg['VpcId']
            
            # Check if default SG has any rules
            has_ingress = len(sg.get('IpPermissions', [])) > 0
            has_egress = len(sg.get('IpPermissionsEgress', [])) > 0
            
            if has_ingress or has_egress:
                violations.append(ViolationDetail(
                    offender_identity=f'default-sg-{vpc_id}',
                    offender_account=sg['OwnerId'],
                    action_taken='Default security group allows traffic',
                    resource_affected=sg_id,
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
        
    def _check_nacl_rules(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check NACL rules"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        ports = params.get('ports', [22, 3389])
        violations = []
        
        # Get all NACLs
        response = self.ec2_client.describe_network_acls()
        
        for nacl in response['NetworkAcls']:
            nacl_id = nacl['NetworkAclId']
            
            # Check ingress rules
            for entry in nacl.get('Entries', []):
                if not entry.get('Egress', True):  # Ingress rule
                    rule_action = entry.get('RuleAction', '')
                    cidr_block = entry.get('CidrBlock', '')
                    
                    if rule_action == 'allow' and (cidr_block == '0.0.0.0/0' or cidr_block == '::/0'):
                        # Check port range
                        port_range = entry.get('PortRange', {})
                        from_port = port_range.get('From', 0)
                        to_port = port_range.get('To', 65535)
                        
                        for port in ports:
                            if from_port <= port <= to_port:
                                violations.append(ViolationDetail(
                                    offender_identity=f'NACL-{nacl_id}',
                                    offender_account=nacl['OwnerId'],
                                    action_taken=f'NACL allows {cidr_block} to port {port}',
                                    resource_affected=nacl_id,
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
        
    def _build_cloudtrail_filter(self, control_config: Dict[str, Any]) -> str:
        """Build CloudTrail filter for network events"""
        check_type = control_config['interrogation']['parameters'].get('check_type')
        
        if check_type == 'ingress_rules':
            return '{ $.eventName = AuthorizeSecurityGroupIngress || $.eventName = RevokeSecurityGroupIngress }'
        elif check_type == 'default_sg_rules':
            return '{ $.eventName = AuthorizeSecurityGroupIngress || $.eventName = AuthorizeSecurityGroupEgress }'
        elif check_type == 'nacl_rules':
            return '{ $.eventName = CreateNetworkAclEntry || $.eventName = ReplaceNetworkAclEntry }'
        else:
            return ''
            
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event for network violations"""
        event_name = event.get('eventName', '')
        
        # Extract user identity
        offender, account_id, offender_arn = self._extract_user_identity(event)
        
        # Build resource identifier
        request_params = event.get('requestParameters', {})
        resource_id = request_params.get('groupId', request_params.get('networkAclId', 'Unknown'))
        
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
