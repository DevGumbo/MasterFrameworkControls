"""
Interrogator Registry
Auto-discovers and manages interrogator classes
"""

import importlib
import inspect
import logging
from pathlib import Path
from typing import Dict, Type, Any, List

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from interrogators.base_interrogator import BaseInterrogator

logger = logging.getLogger(__name__)


class InterrogatorRegistry:
    """Registry for interrogator classes"""
    
    def __init__(self):
        """Initialize registry"""
        self.interrogators = {}
        
    def discover(self, interrogator_dir: str) -> Dict[str, Type[BaseInterrogator]]:
        """
        Discover interrogator classes in directory
        
        Args:
            interrogator_dir: Directory containing interrogator modules
            
        Returns:
            Dictionary of interrogator classes
        """
        interrogator_path = Path(interrogator_dir)
        
        # Scan AWS interrogators
        aws_path = interrogator_path / 'aws'
        if aws_path.exists():
            for py_file in aws_path.glob('*.py'):
                if py_file.name.startswith('__'):
                    continue
                    
                module_name = py_file.stem
                
                try:
                    # Import module
                    dotted_path = f"interrogators.aws.{module_name}"
                    spec = importlib.util.spec_from_file_location(dotted_path, py_file)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[dotted_path] = module  # ✅ register it
                    spec.loader.exec_module(module)
                    
                    # Find interrogator classes
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, BaseInterrogator) and 
                            obj != BaseInterrogator):
                            
                            self.interrogators[name] = obj
                            logger.info(f"Registered interrogator: {name}")
                            
                except Exception as e:
                    logger.error(f"Error loading {py_file}: {str(e)}")
                    
        return self.interrogators
        
    def get_interrogator(self, class_name: str, aws_config: Dict[str, Any]) -> BaseInterrogator:
        """
        Get an interrogator instance
        
        Args:
            class_name: Name of interrogator class
            aws_config: AWS configuration
            
        Returns:
            Interrogator instance
        """
        if class_name not in self.interrogators:
            raise ValueError(f"Unknown interrogator: {class_name}")
            
        interrogator_class = self.interrogators[class_name]
        return interrogator_class(aws_config)
        
    def list_interrogators(self) -> List[str]:
        """List available interrogator classes"""
        return list(self.interrogators.keys())
