"""Command-line interface for PrivaseeAI.Security."""

import json
import sys
import time
from pathlib import Path

import click

from privaseeai_security import __version__
from privaseeai_security.core.config import get_settings, reload_settings
from privaseeai_security.core.logger import get_logger, setup_logger
from privaseeai_security.ios import BackupMonitor, extract_device_info, find_backup_directories


@click.group()
@click.version_option(version=__version__, prog_name="privaseeai")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode",
)
def cli(config: str | None, debug: bool) -> None:
    """PrivaseeAI.Security - Continuous iOS Threat Detection & Monitoring System."""
    # Reload settings if custom config provided
    if config:
        reload_settings(config)

    # Set up logging
    settings = get_settings()
    if debug:
        settings.debug = True
        settings.logging.level = "DEBUG"

    setup_logger()


@cli.command()
@click.argument("backup_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    "--interval",
    type=int,
    help="Monitoring interval in seconds",
)
def monitor(backup_path: str, interval: int | None) -> None:
    """Start continuous monitoring of an iOS backup directory.

    BACKUP_PATH: Path to the iOS backup directory to monitor
    """
    logger = get_logger()
    backup_dir = Path(backup_path)

    click.echo(f"Starting backup monitoring: {backup_dir}")
    click.echo("Press Ctrl+C to stop\n")

    try:
        monitor_obj = BackupMonitor(backup_dir)

        # Display device info
        try:
            device_info = monitor_obj.load_device_info()
            click.echo("Device Information:")
            click.echo(f"  Name: {device_info.device_name}")
            click.echo(f"  Model: {device_info.device_model or device_info.product_type}")
            click.echo(f"  iOS Version: {device_info.product_version}")
            click.echo(f"  Serial: {device_info.serial_number}")
            click.echo(f"  UDID: {device_info.unique_identifier}\n")
        except Exception as e:
            logger.error(f"Failed to load device info: {e}")
            click.echo(f"Warning: Could not load device info: {e}\n", err=True)

        # Start monitoring
        monitor_obj.start()

        # Keep running until interrupted
        try:
            while True:
                time.sleep(interval or 60)
        except KeyboardInterrupt:
            click.echo("\nStopping monitor...")
            monitor_obj.stop()
            click.echo("Monitor stopped.")

    except Exception as e:
        logger.error(f"Monitoring error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("backup_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    "--output",
    type=click.Path(),
    help="Output file for scan results (JSON)",
)
def scan(backup_path: str, output: str | None) -> None:
    """Perform a one-time scan of an iOS backup.

    BACKUP_PATH: Path to the iOS backup directory to scan
    """
    logger = get_logger()
    backup_dir = Path(backup_path)

    click.echo(f"Scanning backup: {backup_dir}\n")

    try:
        monitor_obj = BackupMonitor(backup_dir)
        results = monitor_obj.scan_backup()

        # Display results
        click.echo("Scan Results:")
        click.echo(f"  Device: {results.get('device_info', {}).get('device_name', 'Unknown')}")
        click.echo(
            f"  iOS Version: {results.get('device_info', {}).get('product_version', 'Unknown')}"
        )
        click.echo(f"  Encrypted: {results.get('is_encrypted', False)}")
        click.echo(f"  Files: {results.get('file_count', 0)}")
        click.echo(f"  Apps: {len(results.get('installed_apps', []))}")

        if results.get("error"):
            click.echo(f"\nError: {results['error']}", err=True)

        # Save to file if requested
        if output:
            output_path = Path(output)
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            click.echo(f"\nResults saved to: {output_path}")

    except Exception as e:
        logger.error(f"Scan error: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command(name="device-info")
@click.argument("backup_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON",
)
def device_info(backup_path: str, output_json: bool) -> None:
    """Display device information from an iOS backup.

    BACKUP_PATH: Path to the iOS backup directory
    """
    logger = get_logger()
    backup_dir = Path(backup_path)

    try:
        device = extract_device_info(backup_dir)

        if output_json:
            click.echo(json.dumps(device.to_dict(), indent=2, default=str))
        else:
            click.echo(str(device))

    except Exception as e:
        logger.error(f"Error extracting device info: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def status() -> None:
    """Check system status and configuration."""
    settings = get_settings()

    click.echo("PrivaseeAI.Security Status\n")
    click.echo(f"Version: {__version__}")
    click.echo(f"Environment: {settings.app_env.value}")
    click.echo(f"Debug Mode: {settings.debug}")
    click.echo("\nConfiguration:")
    click.echo(f"  Database: {settings.database.host}:{settings.database.port}")
    click.echo(f"  Redis: {settings.redis.host}:{settings.redis.port}")
    click.echo(f"  Backup Path: {settings.ios_backup.backup_path}")
    click.echo(f"  Monitoring: {'Enabled' if settings.monitoring.enabled else 'Disabled'}")


@cli.command()
@click.option(
    "--output",
    type=click.Path(),
    default=".env",
    help="Output file path (default: .env)",
)
def init(output: str) -> None:
    """Initialize configuration file from template."""
    output_path = Path(output)

    if output_path.exists() and not click.confirm(f"{output_path} already exists. Overwrite?"):
        click.echo("Aborted.")
        return

    # Try to find .env.example in the project root
    # First try the package approach
    try:
        # Get the package directory
        import privaseeai_security

        package_dir = Path(privaseeai_security.__file__).parent
        project_root = package_dir.parent.parent
        example_path = project_root / ".env.example"
    except Exception:
        # Fallback to relative path from current file
        example_path = Path(__file__).parent.parent.parent.parent / ".env.example"

    if not example_path.exists():
        click.echo("Error: .env.example not found", err=True)
        sys.exit(1)

    try:
        with open(example_path) as f:
            content = f.read()

        with open(output_path, "w") as f:
            f.write(content)

        click.echo(f"Configuration file created: {output_path}")
        click.echo("Please edit the file and update the settings.")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("backups_root", type=click.Path(exists=True, file_okay=False, dir_okay=True))
def list_backups(backups_root: str) -> None:
    """List all iOS backup directories in a root directory.

    BACKUPS_ROOT: Root directory containing iOS backups
    """
    logger = get_logger()
    root_dir = Path(backups_root)

    click.echo(f"Searching for backups in: {root_dir}\n")

    try:
        backup_dirs = find_backup_directories(root_dir)

        if not backup_dirs:
            click.echo("No backup directories found.")
            return

        click.echo(f"Found {len(backup_dirs)} backup(s):\n")

        for backup_dir in backup_dirs:
            try:
                device = extract_device_info(backup_dir)
                click.echo(f"  {backup_dir.name}")
                click.echo(f"    Device: {device.device_name}")
                click.echo(f"    Model: {device.device_model or device.product_type}")
                click.echo(f"    iOS: {device.product_version}")
                click.echo(f"    Last Backup: {device.last_backup_date or 'Unknown'}\n")
            except Exception as e:
                logger.debug(f"Could not parse {backup_dir}: {e}")
                click.echo(f"  {backup_dir.name} (could not parse)\n")

    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
