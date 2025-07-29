"""
Base Interrogator Class
All interrogators must inherit from this base class
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import boto3
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class ViolationDetail:
    """Details about a specific violation"""
    # WHO did it
    offender_identity: str  # User, role, or service name
    offender_account: str
    
    # WHAT they did
    action_taken: str  # API call or configuration
    resource_affected: str  # ARN or resource ID
    
    # Optional fields
    offender_arn: Optional[str] = None
    violation_timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    access_method: Optional[str] = None  # Console, CLI, SDK
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        result = {
            'offender': self.offender_identity,
            'account': self.offender_account,
            'action': self.action_taken,
            'resource': self.resource_affected
        }
        
        if self.offender_arn:
            result['offender_arn'] = self.offender_arn
        if self.violation_timestamp:
            result['timestamp'] = self.violation_timestamp.isoformat()
        if self.source_ip:
            result['source_ip'] = self.source_ip
        if self.access_method:
            result['access_method'] = self.access_method
            
        return result


@dataclass
class InterrogationResult:
    """Result of an interrogation"""
    control_id: str
    violation_type: str  # 'historical' or 'current'
    violations: List[ViolationDetail]
    summary: Dict[str, Any]
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'control_id': self.control_id,
            'violation_type': self.violation_type,
            'violations': [v.to_dict() for v in self.violations],
            'summary': self.summary
        }


class BaseInterrogator(ABC):
    """Base class for all interrogators"""
    
    def __init__(self, aws_config: Dict[str, Any]):
        """
        Initialize interrogator with AWS configuration
        
        Args:
            aws_config: Dictionary containing AWS configuration
                - region: AWS region
                - account_ids: List of organization account IDs
                - cloudtrail_log_group: CloudTrail log group name
        """
        self.region = aws_config.get('region', 'us-east-1')
        self.org_accounts = set(aws_config.get('account_ids', []))
        self.cloudtrail_log_group = aws_config.get('cloudtrail_log_group', 'CloudTrail')
        
        # Initialize AWS clients
        self.session = boto3.Session(region_name=self.region)
        self._init_clients()
        
    def _init_clients(self):
        """Initialize AWS clients needed by this interrogator"""
        self.logs_client = self.session.client('logs')
        
    @abstractmethod
    def execute(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> InterrogationResult:
        """
        Execute the interrogation
        
        Args:
            control_config: Control configuration from JSON
            context: Execution context (timeframe, filters, etc.)
            
        Returns:
            InterrogationResult with violations found
        """
        pass
        
    @abstractmethod
    def get_required_permissions(self) -> List[str]:
        """
        Get list of IAM permissions required by this interrogator
        
        Returns:
            List of IAM permission strings
        """
        pass
        
    def check_cloudtrail(self, control_config: Dict[str, Any], context: Dict[str, Any]) -> List[ViolationDetail]:
        """
        Check CloudTrail for historical violations
        
        Args:
            control_config: Control configuration
            context: Execution context
            
        Returns:
            List of violation details
        """
        violations = []
        days_back = context.get('days_back', 30)
        
        # Build CloudTrail filter based on control config
        filter_pattern = self._build_cloudtrail_filter(control_config)
        
        if not filter_pattern:
            return violations
            
        try:
            # Search CloudTrail logs
            end_time = datetime.utcnow()
            start_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            start_time = start_time.replace(day=start_time.day - days_back)
            
            response = self.logs_client.filter_log_events(
                logGroupName=self.cloudtrail_log_group,
                startTime=int(start_time.timestamp() * 1000),
                endTime=int(end_time.timestamp() * 1000),
                filterPattern=filter_pattern,
                limit=100  # Limit for v1.0
            )
            
            # Process events
            for event in response.get('events', []):
                try:
                    log_data = json.loads(event['message'])
                    violation = self._process_cloudtrail_event(log_data, control_config)
                    if violation:
                        violations.append(violation)
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            logger.error(f"Error searching CloudTrail: {str(e)}")
            
        return violations
        
    def _build_cloudtrail_filter(self, control_config: Dict[str, Any]) -> str:
        """Build CloudTrail filter pattern - override in subclasses"""
        return ""
        
    def _process_cloudtrail_event(self, event: Dict[str, Any], control_config: Dict[str, Any]) -> Optional[ViolationDetail]:
        """Process CloudTrail event - override in subclasses"""
        return None
        
    def _extract_user_identity(self, event: Dict[str, Any]) -> tuple:
        """Extract user identity from CloudTrail event"""
        user_identity = event.get('userIdentity', {})
        
        # Determine offender identity
        identity_type = user_identity.get('type', 'Unknown')
        if identity_type == 'IAMUser':
            offender = user_identity.get('userName', 'Unknown')
            offender_arn = user_identity.get('arn', '')
        elif identity_type == 'AssumedRole':
            session_name = user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName', '')
            role_name = user_identity.get('arn', '').split('/')[-2] if '/' in user_identity.get('arn', '') else 'Unknown'
            offender = f"{role_name}/{session_name}" if session_name else role_name
            offender_arn = user_identity.get('arn', '')
        elif identity_type == 'Root':
            offender = 'root'
            offender_arn = user_identity.get('arn', '')
        else:
            offender = identity_type
            offender_arn = user_identity.get('arn', '')
            
        account_id = user_identity.get('accountId', 'Unknown')
        
        return offender, account_id, offender_arn
