"""
Compliance Monitoring Interrogator
Checks AWS Config and CloudWatch monitoring settings
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from ..base_interrogator import BaseInterrogator, ViolationDetail, InterrogationResult
import logging

logger = logging.getLogger(__name__)


class ComplianceMonitoringInterrogator(BaseInterrogator):
    """Interrogator for compliance monitoring controls"""
    
    def _init_clients(self):
        """Initialize AWS clients"""
        super()._init_clients()
        self.config_client = self.session.client('config')
        self.cloudwatch_client = self.session.client('cloudwatch')
        
    def get_required_permissions(self) -> List[str]:
        """Get required IAM permissions"""
        return [
            'config:DescribeConfigurationRecorders',
            'config:DescribeConfigurationRecorderStatus',
            'config:DescribeDeliveryChannels',
            'config:DescribeDeliveryChannelStatus',
            'cloudwatch:DescribeAlarms',
            'logs:FilterLogEvents'
        ]
        
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Execute compliance monitoring interrogation"""
        control_id = control_config['control_id']
        params = control_config['interrogation']['parameters']
        check_type = params.get('check_type', 'aws_config_enabled')
        
        # Route to appropriate check method
        if check_type == 'aws_config_enabled':
            return self._check_aws_config_enabled(control_config, context)
        else:
            return InterrogationResult(
                control_id=control_id,
                violation_type='error',
                violations=[],
                summary={'error': f'Unknown check type: {check_type}'}
            )
            
    def _check_aws_config_enabled(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """Check if AWS Config is enabled and properly configured"""
        control_id = control_config['control_id']
        title = control_config.get('title', '').lower()
        violations = []
        
        try:
            # Check configuration recorders
            recorders_response = self.config_client.describe_configuration_recorders()
            recorders = recorders_response.get('ConfigurationRecorders', [])
            
            if not recorders:
                violations.append(ViolationDetail(
                    offender_identity='AWS Config',
                    offender_account=self.aws_config['account_ids'][0],
                    action_taken='No configuration recorder found',
                    resource_affected='AWS Config',
                    violation_timestamp=datetime.utcnow()
                ))
            else:
                # Check recorder status
                status_response = self.config_client.describe_configuration_recorder_status()
                
                for status in status_response.get('ConfigurationRecordersStatus', []):
                    if not status.get('recording', False):
                        violations.append(ViolationDetail(
                            offender_identity=status.get('name', 'default'),
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Configuration recorder not recording',
                            resource_affected='AWS Config recorder',
                            violation_timestamp=datetime.utcnow()
                        ))
                        
                    # Check if last status was error
                    if status.get('lastStatus') == 'FAILURE':
                        violations.append(ViolationDetail(
                            offender_identity=status.get('name', 'default'),
                            offender_account=self.aws_config['account_ids'][0],
                            action_taken='Configuration recorder in failed state',
                            resource_affected='AWS Config recorder',
                            violation_timestamp=datetime.utcnow()
                        ))
                        
                # Check delivery channels
                channels_response = self.config_client.describe_delivery_channels()
                channels = channels_response.get('DeliveryChannels', [])
                
                if not channels:
                    violations.append(ViolationDetail(
                        offender_identity='AWS Config',
                        offender_account=self.aws_config['account_ids'][0],
                        action_taken='No delivery channel configured',
                        resource_affected='AWS Config delivery channel',
                        violation_timestamp=datetime.utcnow()
                    ))
                else:
                    # Check delivery channel status
                    channel_status_response = self.config_client.describe_delivery_channel_status()
                    
                    for channel_status in channel_status_response.get('DeliveryChannelsStatus', []):
                        config_history_status = channel_status.get('configHistoryDeliveryInfo', {})
                        if config_history_status.get('lastStatus') == 'FAILURE':
                            violations.append(ViolationDetail(
                                offender_identity=channel_status.get('name', 'default'),
                                offender_account=self.aws_config['account_ids'][0],
                                action_taken='Delivery channel failing to deliver',
                                resource_affected='AWS Config delivery channel',
                                violation_timestamp=datetime.utcnow()
                            ))
                            
                # Check for service-linked role if mentioned in title
                if 'service-linked role' in title:
                    for recorder in recorders:
                        role_arn = recorder.get('roleARN', '')
                        if 'aws-service-role' not in role_arn:
                            violations.append(ViolationDetail(
                                offender_identity=recorder.get('name', 'default'),
                                offender_account=self.aws_config['account_ids'][0],
                                action_taken='Not using service-linked role',
                                resource_affected=role_arn,
                                violation_timestamp=datetime.utcnow()
                            ))
                            
        except Exception as e:
            logger.error(f"Error checking AWS Config: {e}")
            
        # Check CloudTrail for configuration changes
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
        """Build CloudTrail filter for monitoring events"""
        check_type = control_config['interrogation']['parameters'].get('check_type')
        
        if check_type == 'aws_config_enabled':
            return '{ $.eventName = StopConfigurationRecorder || $.eventName = DeleteConfigurationRecorder || $.eventName = DeleteDeliveryChannel }'
        else:
            return ''
            
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event for monitoring violations"""
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
            resource_affected='AWS Config',
            violation_timestamp=datetime.strptime(event['eventTime'], '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=None),
            source_ip=event.get('sourceIPAddress'),
            access_method=event.get('userAgent', '').split('/')[0] if event.get('userAgent') else None
        )
