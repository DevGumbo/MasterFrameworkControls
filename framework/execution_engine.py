"""
Execution Engine
Main execution loop for running control interrogations
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml

from .control_loader import ControlLoader
from .interrogator_registry import InterrogatorRegistry
from .results_processor import ResultsProcessor

logger = logging.getLogger(__name__)


class ExecutionEngine:
    """Main execution engine for control framework"""
    
    def __init__(self, config_file: str):
        """
        Initialize execution engine
        
        Args:
            config_file: Path to configuration file
        """
        # Load configuration
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
            
        # Initialize components
        self.control_loader = ControlLoader(self.config['paths']['control_definitions'])
        self.interrogator_registry = InterrogatorRegistry()
        self.results_processor = ResultsProcessor()
        
        # AWS configuration
        self.aws_config = {
            'region': self.config.get('aws', {}).get('region', 'us-east-1'),
            'account_ids': self.config.get('aws', {}).get('organization_accounts', []),
            'cloudtrail_log_group': self.config.get('aws', {}).get('cloudtrail_log_group', 'CloudTrail')
        }
        
        # Execution context
        self.context = {
            'days_back': self.config.get('analysis', {}).get('days_back', 30),
            'execution_time': datetime.utcnow()
        }
        
    def initialize(self):
        """Initialize the engine components"""
        # Load controls
        logger.info("Loading control definitions...")
        controls = self.control_loader.load_controls()
        logger.info(f"Loaded {len(controls)} controls")
        
        # Discover interrogators
        logger.info("Discovering interrogators...")
        interrogators = self.interrogator_registry.discover(self.config['paths']['interrogators'])
        logger.info(f"Found {len(interrogators)} interrogators")
        
    def execute(self, 
                standard: Optional[str] = None,
                services: Optional[List[str]] = None,
                control_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute control interrogations
        
        Args:
            standard: Standard to check (e.g., 'cis_v3_0')
            services: List of services to check
            control_ids: Specific control IDs to check
            
        Returns:
            Execution results
        """
        # Initialize if not done
        if not self.control_loader.controls:
            self.initialize()
            
        # Determine which controls to execute
        if control_ids:
            controls_to_execute = [
                self.control_loader.get_control(cid) 
                for cid in control_ids 
                if self.control_loader.get_control(cid)
            ]
        elif standard:
            controls_to_execute = self.control_loader.get_controls_by_standard(
                standard.split('_')[0], 
                '_'.join(standard.split('_')[1:]) if '_' in standard else None
            )
        else:
            controls_to_execute = list(self.control_loader.controls.values())
            
        # Filter by services if specified
        if services:
            controls_to_execute = [
                c for c in controls_to_execute 
                if c.get('service') in services
            ]
            
        logger.info(f"Executing {len(controls_to_execute)} controls")
        
        # Execute controls
        results = []
        for control in controls_to_execute:
            try:
                result = self._execute_control(control)
                results.append(result)
            except Exception as e:
                logger.error(f"Error executing control {control['control_id']}: {str(e)}")
                
        # Process results
        processed_results = self.results_processor.process(results)
        
        return {
            'execution_time': self.context['execution_time'],
            'controls_executed': len(controls_to_execute),
            'results': processed_results
        }
        
    def _execute_control(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single control"""
        control_id = control['control_id']
        logger.info(f"Executing control: {control_id} - {control['title']}")
        
        # Get interrogator
        interrogator_class = control['interrogation']['class']
        interrogator = self.interrogator_registry.get_interrogator(
            interrogator_class, 
            self.aws_config
        )
        
        # Execute interrogation
        result = interrogator.execute(control, self.context)
        
        # Add control metadata to result
        return {
            'control': control,
            'result': result.to_dict()
        }
