#!/usr/bin/env python3
"""
Test script to verify framework setup
"""

import sys
from pathlib import Path

# Add framework to path
sys.path.append(str(Path(__file__).parent))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from framework.control_loader import ControlLoader
        print("✓ ControlLoader imported")
    except Exception as e:
        print(f"✗ ControlLoader import failed: {e}")
        
    try:
        from framework.interrogator_registry import InterrogatorRegistry
        print("✓ InterrogatorRegistry imported")
    except Exception as e:
        print(f"✗ InterrogatorRegistry import failed: {e}")
        
    try:
        from framework.execution_engine import ExecutionEngine
        print("✓ ExecutionEngine imported")
    except Exception as e:
        print(f"✗ ExecutionEngine import failed: {e}")
        
    try:
        from interrogators.base_interrogator import BaseInterrogator
        print("✓ BaseInterrogator imported")
    except Exception as e:
        print(f"✗ BaseInterrogator import failed: {e}")


def test_control_loading():
    """Test control loading"""
    print("\nTesting control loading...")
    
    try:
        from framework.control_loader import ControlLoader
        loader = ControlLoader('./control_definitions')
        controls = loader.load_controls()
        print(f"✓ Loaded {len(controls)} controls")
        
        # List services
        services = set(c.get('service') for c in controls.values())
        print(f"  Services: {', '.join(services)}")
        
    except Exception as e:
        print(f"✗ Control loading failed: {e}")


def test_interrogator_discovery():
    """Test interrogator discovery"""
    print("\nTesting interrogator discovery...")
    
    try:
        from framework.interrogator_registry import InterrogatorRegistry
        registry = InterrogatorRegistry()
        interrogators = registry.discover('./interrogators')
        print(f"✓ Discovered {len(interrogators)} interrogators")
        
        for name in interrogators:
            print(f"  - {name}")
            
    except Exception as e:
        print(f"✗ Interrogator discovery failed: {e}")


if __name__ == '__main__':
    print("AWS Security Control Framework - Setup Test")
    print("="*50)
    
    test_imports()
    test_control_loading()
    test_interrogator_discovery()
    
    print("\nSetup test complete!")
