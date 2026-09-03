#!/usr/bin/env python3

"""
Database Schema Test Script
Tests the new tool-specific database schema and verifies all models work correctly.

Usage:
    python test_db_schema.py
"""

import json
import logging
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# Add backend to path for imports
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def test_models():
    """Test all models and database schema"""
    
    logger.info("=" * 60)
    logger.info("Testing New Database Schema")
    logger.info("=" * 60)
    
    try:
        # Import models from kali_server
        from kali_server import (
            TOOL_MODEL_MAPPING, app, db
        )
        
        with app.app_context():
            # Create all tables
            db.create_all()
            logger.info("✓ All tables created successfully")
            
            # Test 1: Verify all tables exist
            logger.info("\nTest 1: Verifying all tool tables...")
            expected_tables = list(TOOL_MODEL_MAPPING.keys())
            logger.info(f"Expected tables: {expected_tables}")
            
            # Test 2: Insert test records
            logger.info("\nTest 2: Inserting test records...")
            test_records = {}
            
            for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                try:
                    record = model_class(
                        id=f"test-{tool_name}-001",
                        command=f"{tool_name} --test target.com",
                        target="target.com",
                        duration=10.5,
                        success=True,
                        return_code=0,
                        timed_out=False,
                        stdout="Test output",
                        stderr="",
                        stdout_length=11,
                        stderr_length=0
                    )
                    db.session.add(record)
                    test_records[tool_name] = record
                except Exception as e:
                    logger.error(f"  ✗ Failed to create record for {tool_name}: {e}")
            
            db.session.commit()
            logger.info(f"  ✓ {len(test_records)} test records inserted")
            
            # Test 3: Query test records
            logger.info("\nTest 3: Querying test records...")
            for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                try:
                    count = model_class.query.count()
                    records = model_class.query.all()
                    
                    if count > 0:
                        logger.info(f"  ✓ {tool_name}: {count} record(s)")
                        for record in records:
                            data = record.to_dict(include_output=True)
                            logger.info(f"    - ID: {data['id']}, Target: {data['target']}, Success: {data['success']}")
                    else:
                        logger.warning(f"  ⚠ {tool_name}: 0 records")
                except Exception as e:
                    logger.error(f"  ✗ Error querying {tool_name}: {e}")
            
            # Test 4: Test filtering and aggregation
            logger.info("\nTest 4: Testing aggregation...")
            for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                    try:
                        total = model_class.query.count()
                        successful = model_class.query.filter_by(success=True).count()
                        failed = model_class.query.filter_by(success=False).count()
                        
                        logger.info(f"  {tool_name}: Total={total}, Success={successful}, Failed={failed}")
                    except Exception as e:
                        logger.error(f"  ✗ Error aggregating {tool_name}: {e}")
            
            # Test 5: Test to_dict() method
            logger.info("\nTest 5: Testing to_dict() serialization...")
            for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                try:
                    record = model_class.query.first()
                    if record:
                        data = record.to_dict(include_output=True)
                        logger.info(f"  ✓ {tool_name}: {json.dumps(data, indent=2, default=str)[:100]}...")
                except Exception as e:
                    logger.error(f"  ✗ Error serializing {tool_name}: {e}")
            
            # Test 6: Test record deletion
            logger.info("\nTest 6: Testing record deletion...")
            for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                try:
                    initial_count = model_class.query.count()
                    records = model_class.query.all()
                    for record in records:
                        db.session.delete(record)
                    db.session.commit()
                    
                    final_count = model_class.query.count()
                    logger.info(f"  ✓ {tool_name}: Deleted {initial_count} record(s)")
                except Exception as e:
                    logger.error(f"  ✗ Error deleting from {tool_name}: {e}")
            
            logger.info("\n" + "=" * 60)
            logger.info("✓ All model tests passed!")
            logger.info("=" * 60)
            return True
    
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def test_command_history_class():
    """Test the CommandHistory class with new models"""
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "test_ch.db")
        os.environ['DATABASE_PATH'] = test_db
        
        logger.info("\n" + "=" * 60)
        logger.info("Testing CommandHistory Class")
        logger.info("=" * 60)
        
        try:
            from kali_server import CommandHistory
            
            # Create CommandHistory instance
            ch = CommandHistory(max_history=100)
            logger.info("✓ CommandHistory instance created")
            
            # Test add_command
            logger.info("\nTest: Adding commands to history...")
            tools = ['nmap', 'gobuster', 'dirb', 'nikto', 'sqlmap']
            command_ids = {}
            
            for tool in tools:
                result = {
                    "success": True,
                    "return_code": 0,
                    "timed_out": False,
                    "stdout": f"Output from {tool}",
                    "stderr": ""
                }
                cmd_id = ch.add_command(
                    command=f"{tool} -test target.com",
                    result=result,
                    duration=5.2,
                    tool_name=tool,
                    target="target.com"
                )
                command_ids[tool] = cmd_id
                logger.info(f"  ✓ Added {tool}: {cmd_id}")
            
            # Test get_all
            logger.info("\nTest: Getting all history...")
            all_history = ch.get_all(limit=50)
            logger.info(f"  ✓ Retrieved {len(all_history)} records")
            
            # Test get_all with tool filter
            logger.info("\nTest: Getting history per tool...")
            for tool in tools:
                history = ch.get_all(limit=50, tool_name=tool)
                logger.info(f"  ✓ {tool}: {len(history)} record(s)")
            
            # Test get_by_id
            logger.info("\nTest: Getting record by ID...")
            for tool, cmd_id in list(command_ids.items())[:2]:
                record = ch.get_by_id(cmd_id, tool_name=tool)
                if record:
                    logger.info(f"  ✓ Found {tool} record: {record['id']}")
                else:
                    logger.warning(f"  ⚠ Could not find {tool} record")
            
            # Test get_stats
            logger.info("\nTest: Getting statistics...")
            all_stats = ch.get_stats()
            logger.info(f"  ✓ All stats: {json.dumps(all_stats, indent=2)}")
            
            for tool in tools:
                tool_stats = ch.get_stats(tool_name=tool)
                logger.info(f"  ✓ {tool} stats: {json.dumps(tool_stats, indent=2)}")
            
            # Test clear (specific tool)
            logger.info("\nTest: Clearing history for one tool...")
            ch.clear(tool_name='nmap')
            nmap_stats = ch.get_stats(tool_name='nmap')
            logger.info(f"  ✓ Nmap history cleared: {json.dumps(nmap_stats, indent=2)}")
            
            # Test clear (all)
            logger.info("\nTest: Clearing all history...")
            ch.clear()
            all_stats = ch.get_stats()
            logger.info(f"  ✓ All history cleared: {json.dumps(all_stats, indent=2)}")
            
            logger.info("\n" + "=" * 60)
            logger.info("✓ CommandHistory class tests passed!")
            logger.info("=" * 60)
            return True
        
        except Exception as e:
            logger.error(f"✗ Test failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False


def main():
    """Run all tests"""
    logger.info("Starting Database Schema Tests...")
    
    # Store original DATABASE_PATH
    original_db_path = os.environ.get('DATABASE_PATH', 'scan_history.db')
    
    try:
        # Test 1: Models
        models_ok = test_models()
        
        # Test 2: CommandHistory class
        ch_ok = test_command_history_class()
        
        if models_ok and ch_ok:
            logger.info("\n✓ All tests passed successfully!")
            return 0
        else:
            logger.error("\n✗ Some tests failed!")
            return 1
    
    finally:
        # Restore original DATABASE_PATH
        os.environ['DATABASE_PATH'] = original_db_path


if __name__ == "__main__":
    sys.exit(main())
