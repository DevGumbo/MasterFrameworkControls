"""
Control Loader
Loads control definitions from JSON files
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class ControlLoader:
    """Loads control definitions from JSON files"""
    
    def __init__(self, control_dir: str):
        """
        Initialize control loader
        
        Args:
            control_dir: Directory containing control JSON files
        """
        self.control_dir = Path(control_dir)
        self.controls = {}
        self.standards_mapping = {}
        
    def load_controls(self, services: List[str] = None) -> Dict[str, Any]:
        """
        Load control definitions
        
        Args:
            services: List of services to load controls for (None = all)
            
        Returns:
            Dictionary of controls indexed by control_id
        """
        # Load AWS controls
        aws_dir = self.control_dir / 'aws'
        if aws_dir.exists():
            for json_file in aws_dir.glob('*.json'):
                service = json_file.stem.replace('_controls', '')
                
                # Skip if not in requested services
                if services and service not in services:
                    continue
                    
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        
                    # Add controls to dictionary
                    for control in data.get('controls', []):
                        control_id = control['control_id']
                        control['service'] = service
                        self.controls[control_id] = control
                        
                    logger.info(f"Loaded {len(data.get('controls', []))} controls from {json_file.name}")
                    
                except Exception as e:
                    logger.error(f"Error loading {json_file}: {str(e)}")
                    
        # Load standards mappings
        standards_dir = self.control_dir / 'standards'
        if standards_dir.exists():
            for mapping_file in standards_dir.glob('*.json'):
                standard = mapping_file.stem.replace('_mapping', '')
                
                try:
                    with open(mapping_file, 'r') as f:
                        self.standards_mapping[standard] = json.load(f)
                        
                except Exception as e:
                    logger.error(f"Error loading mapping {mapping_file}: {str(e)}")
                    
        return self.controls
        
    def get_controls_by_standard(self, standard: str, version: str = None) -> List[Dict[str, Any]]:
        """
        Get controls for a specific standard
        
        Args:
            standard: Standard name (e.g., 'cis')
            version: Standard version (e.g., 'v3_0')
            
        Returns:
            List of controls for that standard
        """
        standard_key = f"{standard}_{version}" if version else standard
        controls = []
        
        # Find all controls that have this standard
        for control_id, control in self.controls.items():
            if standard_key in control.get('standards', {}):
                controls.append(control)
                
        return controls
        
    def get_control(self, control_id: str) -> Dict[str, Any]:
        """
        Get a specific control by ID
        
        Args:
            control_id: Control identifier
            
        Returns:
            Control definition or None
        """
        return self.controls.get(control_id)
