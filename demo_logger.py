#!/usr/bin/env python3
"""Demo script to showcase the production-ready logging system."""

import tempfile
from pathlib import Path
from privaseeai_security.logger import (
    setup_logger,
    setup_production_logger,
    configure_structlog,
    get_structlog,
)


def demo_basic_logger():
    """Demo backward-compatible basic logger."""
    print("\n" + "=" * 60)
    print("1. BASIC LOGGER (Backward Compatible)")
    print("=" * 60)
    
    logger = setup_logger(name="demo_basic", level="INFO", log_format="json")
    logger.info("This is a basic info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    print("✓ Basic logger works (backward compatible)")


def demo_production_logger():
    """Demo production logger with rotation."""
    print("\n" + "=" * 60)
    print("2. PRODUCTION LOGGER (File Rotation + Compression)")
    print("=" * 60)
    
    # Use temp directory for demo
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)
        
        # Setup production logger
        logger = setup_production_logger(
            name="demo_production",
            level="INFO",
            log_dir=log_dir,
            enable_console=True,
            enable_rich=False,
        )
        
        logger.info("Production logger initialized")
        logger.info("Writing to: %s", log_dir)
        logger.warning("This log will be rotated at 100 MB")
        logger.error("Old logs will be compressed with gzip")
        
        # Show created files
        log_files = list(log_dir.glob("*.log"))
        print(f"\n✓ Created {len(log_files)} log file(s):")
        for f in log_files:
            print(f"  - {f.name}")


def demo_rich_logger():
    """Demo production logger with Rich console output."""
    print("\n" + "=" * 60)
    print("3. PRODUCTION LOGGER WITH RICH CONSOLE (Development Mode)")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)
        
        # Setup with Rich console handler
        logger = setup_production_logger(
            name="demo_rich",
            level="INFO",
            log_dir=log_dir,
            enable_console=True,
            enable_rich=True,  # Enable Rich for pretty console output
        )
        
        logger.info("Rich console output enabled")
        logger.warning("Pretty colors and formatting!")
        logger.error("Tracebacks will be beautiful", extra={"user": "demo"})
        print("\n✓ Rich logger works (pretty console output)")


def demo_structlog():
    """Demo structlog integration."""
    print("\n" + "=" * 60)
    print("4. STRUCTLOG (Structured Logging)")
    print("=" * 60)
    
    # Configure structlog for development
    configure_structlog(development_mode=True)
    
    # Get a structlog instance
    logger = get_structlog("demo_structlog")
    
    logger.info("structured_message", user_id=123, action="login", ip="192.168.1.1")
    logger.warning("rate_limit_exceeded", user_id=456, requests=1000, limit=100)
    logger.error("database_error", error="Connection timeout", db="postgres")
    
    print("\n✓ Structlog works (structured logging with context)")


def demo_rotation_info():
    """Show rotation configuration details."""
    print("\n" + "=" * 60)
    print("5. LOG ROTATION CONFIGURATION")
    print("=" * 60)
    
    print("""
Production Logger Features:
  
  📁 Log Location:
     - Production: /var/log/privaseeai/
     - Fallback: ./logs/ (if /var/log not writable)
  
  🔄 Rotation Policies:
     - Size-based: Rotates at 100 MB (keeps 10 backups)
     - Time-based: Rotates daily at midnight (keeps 30 days)
  
  🗜️  Compression:
     - Old logs are automatically compressed with gzip
     - Saves disk space while retaining history
  
  📊 Log Format:
     - File: JSON structured logs (machine-readable)
     - Console: Human-readable (or Rich for development)
  
  🔧 Usage Examples:
     
     # Basic (backward compatible)
     logger = setup_logger()
     
     # Production (recommended)
     logger = setup_production_logger(
         enable_rich=False  # Production
     )
     
     # Development (pretty output)
     logger = setup_production_logger(
         enable_rich=True   # Development
     )
     
     # Structlog (structured logging)
     configure_structlog(development_mode=True)
     logger = get_structlog()
     logger.info("event", key="value")
    """)


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("PRIVASEEAI.SECURITY - PRODUCTION LOGGING DEMO")
    print("=" * 60)
    
    # Run all demos
    demo_basic_logger()
    demo_production_logger()
    demo_rich_logger()
    demo_structlog()
    demo_rotation_info()
    
    print("\n" + "=" * 60)
    print("✅ ALL DEMOS COMPLETED SUCCESSFULLY")
    print("=" * 60)
    print()
