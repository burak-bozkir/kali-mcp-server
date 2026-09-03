#!/usr/bin/env python3

"""
Database Migration Script
Migrates data from the old single 'scan_history' table to the new tool-specific tables.

Usage:
    python migration.py [--database path/to/database.db] [--backup]

Options:
    --database: Path to the database file (default: scan_history.db)
    --backup: Create a backup of the original database before migration
"""

import argparse
import json
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def setup_flask_app(db_path: str):
    """Setup Flask app and models"""
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy.orm import DeclarativeBase
    
    class Base(DeclarativeBase):
        pass
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app, model_class=Base)
    
    return app, db


def migrate_data(db_path: str, backup: bool = True):
    """
    Migrate data from old schema to new tool-specific tables
    
    Args:
        db_path: Path to the database file
        backup: Whether to create a backup before migration
    """
    
    if not os.path.exists(db_path):
        logger.error(f"Database not found: {db_path}")
        return False
    
    # Create backup if requested
    if backup:
        backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            shutil.copy2(db_path, backup_path)
            logger.info(f"Backup created: {backup_path}")
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return False
    
    try:
        # Import models
        from kali_server import (
            app, db, ScanRecord, NmapHistory, GobusterHistory, DirbHistory,
            NiktoHistory, SqlmapHistory, Enum4linuxHistory, MetasploitHistory,
            HydraHistory, JohnHistory, WpscanHistory, TOOL_MODEL_MAPPING
        )
        
        logger.info("Starting migration...")
        
        with app.app_context():
            # Get all records from old table
            old_records = ScanRecord.query.all()
            total_records = len(old_records)
            
            if total_records == 0:
                logger.info("No records to migrate. Database is empty.")
                return True
            
            logger.info(f"Found {total_records} records to migrate")
            
            migrated_count = 0
            error_count = 0
            
            # Migrate each record
            for old_record in old_records:
                try:
                    tool_name = old_record.tool_name or "nmap"
                    tool_name_lower = tool_name.lower()
                    
                    # Get the correct model class for this tool
                    model_class = TOOL_MODEL_MAPPING.get(tool_name_lower, NmapHistory)
                    
                    # Create new record in tool-specific table
                    new_record = model_class(
                        id=old_record.id,
                        command=old_record.command,
                        target=old_record.target,
                        timestamp=old_record.timestamp,
                        duration=old_record.duration,
                        success=old_record.success,
                        return_code=old_record.return_code,
                        timed_out=old_record.timed_out,
                        stdout=old_record.stdout,
                        stderr=old_record.stderr,
                        stdout_length=old_record.stdout_length,
                        stderr_length=old_record.stderr_length
                    )
                    
                    db.session.add(new_record)
                    migrated_count += 1
                    
                    # Log progress every 10 records
                    if migrated_count % 10 == 0:
                        logger.info(f"Progress: {migrated_count}/{total_records} records migrated")
                
                except Exception as e:
                    logger.error(f"Error migrating record {old_record.id}: {e}")
                    error_count += 1
            
            # Commit all changes
            try:
                db.session.commit()
                logger.info(f"Migration completed successfully: {migrated_count} records migrated, {error_count} errors")
                
                # Print migration summary by tool
                logger.info("\nMigration Summary by Tool:")
                for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                    count = model_class.query.count()
                    if count > 0:
                        logger.info(f"  {tool_name}: {count} records")
                
                return True
            except Exception as e:
                logger.error(f"Failed to commit migration: {e}")
                db.session.rollback()
                return False
    
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def verify_migration(db_path: str):
    """Verify the migration was successful"""
    try:
        from kali_server import app, TOOL_MODEL_MAPPING
        
        with app.app_context():
            logger.info("\nVerifying migration...")
            total = 0
            
            for tool_name, model_class in TOOL_MODEL_MAPPING.items():
                count = model_class.query.count()
                total += count
            
            logger.info(f"Total records in new schema: {total}")
            
            if total > 0:
                logger.info("✓ Migration verified successfully")
                return True
            else:
                logger.warning("⚠ No records found in new schema")
                return False
    
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Migrate Kali MCP Server database to new schema")
    parser.add_argument(
        "--database",
        type=str,
        default="scan_history.db",
        help="Path to the database file (default: scan_history.db)"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        default=True,
        help="Create a backup before migration (default: True)"
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip backup creation"
    )
    
    args = parser.parse_args()
    
    db_path = args.database
    backup = not args.no_backup
    
    logger.info("=" * 60)
    logger.info("Kali MCP Server - Database Migration")
    logger.info("=" * 60)
    logger.info(f"Database: {db_path}")
    logger.info(f"Backup: {'Yes' if backup else 'No'}")
    logger.info("=" * 60)
    
    # Run migration
    if migrate_data(db_path, backup=backup):
        # Verify
        verify_migration(db_path)
        logger.info("\nMigration completed successfully!")
        return 0
    else:
        logger.error("\nMigration failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
