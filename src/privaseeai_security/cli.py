"""Command-line interface for PrivaseeAI Security.

Provides user-friendly commands for:
- Starting/stopping monitoring
- Checking system status
- Running on-demand scans
- Viewing threat history
- Launching web dashboard
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import signal

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import subprocess


from .orchestrator import ThreatOrchestrator, MonitorStatus
from .logger import get_logger
from .crypto.cert_validator import ThreatLevel


logger = get_logger(__name__)
console = Console()


# Global orchestrator instance for signal handling
_orchestrator: Optional[ThreatOrchestrator] = None


def _signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    if _orchestrator:
        console.print("\n[yellow]Received shutdown signal, stopping...[/yellow]")
        asyncio.create_task(_orchestrator.stop())


@click.group()
@click.version_option(version="0.3.0", prog_name="privasee")
def cli():
    """PrivaseeAI Security - iOS Threat Detection & Monitoring.
    
    Continuous real-time protection against iOS device compromise,
    carrier-level attacks, and spyware.
    """
    pass


@cli.command()
@click.option(
    "--backup-path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to iOS backup directory (auto-detected if not specified)"
)
@click.option(
    "--interval",
    type=int,
    default=30,
    help="Monitoring interval in seconds (default: 30)"
)
@click.option(
    "--no-telegram",
    is_flag=True,
    help="Disable Telegram alerts"
)
@click.option(
    "--no-initial-scan",
    is_flag=True,
    help="Skip initial backup scan on startup"
)
def start(
    backup_path: Optional[Path],
    interval: int,
    no_telegram: bool,
    no_initial_scan: bool
):
    """Start continuous threat monitoring.
    
    This starts all monitors and runs continuously until stopped
    with Ctrl+C or the 'stop' command.
    
    Examples:
        privasee start
        privasee start --interval 60
        privasee start --backup-path ~/backups --no-telegram
    """
    global _orchestrator
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    
    console.print(Panel.fit(
        "[bold cyan]PrivaseeAI Security[/bold cyan]\n"
        "🛡️  iOS Threat Detection & Monitoring",
        border_style="cyan"
    ))
    
    async def run_monitoring():
        global _orchestrator
        
        _orchestrator = ThreatOrchestrator(
            backup_path=backup_path,
            telegram_enabled=not no_telegram,
            monitor_interval=interval,
            scan_backups_on_start=not no_initial_scan
        )
        
        try:
            await _orchestrator.start()
            
            console.print("\n[green]✅ Monitoring started successfully[/green]")
            console.print(f"[dim]Press Ctrl+C to stop[/dim]\n")
            
            # Keep running and show periodic status
            while True:
                await asyncio.sleep(60)  # Status update every minute
                status = _orchestrator.get_status()
                
                if status.threats_detected > 0:
                    summary = _orchestrator.get_threat_summary()
                    _print_threat_summary(summary)
                    
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping...[/yellow]")
        finally:
            if _orchestrator:
                await _orchestrator.stop()
    
    try:
        asyncio.run(run_monitoring())
    except KeyboardInterrupt:
        console.print("[green]✅ Stopped[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error("CLI start error", exc_info=e)
        sys.exit(1)


@cli.command()
@click.option(
    "--backup-path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to iOS backup directory"
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show detailed threat information"
)
def scan(backup_path: Optional[Path], verbose: bool):
    """Run one-time security scan of iOS backups.
    
    Performs a comprehensive scan of iOS backups without starting
    continuous monitoring.
    
    Examples:
        privasee scan
        privasee scan --backup-path ~/backups --verbose
    """
    console.print("[cyan]🔍 Running security scan...[/cyan]\n")
    
    async def run_scan():
        orchestrator = ThreatOrchestrator(
            backup_path=backup_path,
            telegram_enabled=False,
            scan_backups_on_start=False
        )
        
        with console.status("[cyan]Scanning backups...[/cyan]"):
            summary = await orchestrator.scan_now()
        
        console.print("[green]✅ Scan complete[/green]\n")
        _print_threat_summary(summary, verbose=verbose)
        
        return summary.total_threats
    
    try:
        threats = asyncio.run(run_scan())
        sys.exit(1 if threats > 0 else 0)
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        logger.error("CLI scan error", exc_info=e)
        sys.exit(1)


@cli.command()
def status():
    """Show current monitoring status.
    
    Displays the status of all monitors, threat counts, and
    system uptime.
    """
    # Note: For MVP, this shows a static message
    # In production, this would connect to a running daemon
    console.print(Panel.fit(
        "[yellow]Status checking requires running daemon[/yellow]\n"
        "Use '[cyan]privasee start[/cyan]' to begin monitoring",
        title="System Status",
        border_style="yellow"
    ))
    
    console.print("\n[dim]Future: Will show real-time status of running monitors[/dim]")


@cli.command()
@click.option(
    "--count",
    type=int,
    default=10,
    help="Number of recent threats to show (default: 10)"
)
def alerts(count: int):
    """Show recent threat alerts.
    
    Displays the most recent security threats detected by
    the monitoring system.
    
    Examples:
        privasee alerts
        privasee alerts --count 50
    """
    # Note: For MVP, this shows a placeholder
    # In production, this would query threat database
    console.print(Panel.fit(
        "[yellow]Alert history requires database[/yellow]\n"
        "Threats are currently logged and sent via Telegram",
        title="Recent Alerts",
        border_style="yellow"
    ))
    
    console.print("\n[dim]Future: Will show threat history from database[/dim]")


@cli.command(context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
def test(pytest_args):
    """Run the test suite using pytest. Additional pytest args are forwarded.

    Examples:
        privasee test
        privasee test -q
        privasee test tests/unit/test_config.py::test_load_config
    """
    cmd = [sys.executable, "-m", "pytest"] + list(pytest_args)
    console.print(f"[cyan]Running tests:[/cyan] {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd)
        sys.exit(res.returncode)
    except KeyboardInterrupt:
        console.print('\n[yellow]Test run cancelled[/yellow]')
        sys.exit(1)


@cli.command()
def config():
    """Show current configuration.
    
    Displays the active configuration settings including
    backup paths, monitoring intervals, and alert settings.
    """
    from .orchestrator import ThreatOrchestrator
    
    # Auto-detect backup path
    backup_path = ThreatOrchestrator._auto_detect_backup_path()
    
    table = Table(title="Configuration", box=box.ROUNDED)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Backup Path", str(backup_path))
    table.add_row("Backup Path Exists", "✅ Yes" if backup_path.exists() else "❌ No")
    table.add_row("Default Interval", "30 seconds")
    table.add_row("Telegram Configured", "✅ Yes" if _check_telegram_config() else "❌ No")
    
    console.print(table)
    
    if not backup_path.exists():
        console.print("\n[yellow]⚠️  Backup path not found![/yellow]")
        console.print("Connect your iOS device and create a backup, or specify path with --backup-path")


def _check_telegram_config() -> bool:
    """Check if Telegram is configured."""
    import os
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))


def _print_threat_summary(summary, verbose: bool = False):
    """Print formatted threat summary."""
    # Create threat summary table
    table = Table(title="🚨 Threat Summary", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Indicator", justify="center")
    
    # Add rows for each severity
    severities = [
        ("CRITICAL", summary.critical_count, "🚨", "red"),
        ("HIGH", summary.high_count, "🔴", "red"),
        ("MEDIUM", summary.medium_count, "🟠", "yellow"),
        ("LOW", summary.low_count, "🟡", "yellow"),
    ]
    
    for severity, count, emoji, color in severities:
        if count > 0 or verbose:
            table.add_row(
                f"[{color}]{severity}[/{color}]",
                f"[{color}]{count}[/{color}]",
                emoji if count > 0 else "—"
            )
    
    console.print(table)
    
    # Show breakdown by source
    if summary.threats_by_source:
        console.print("\n[bold]Threats by Source:[/bold]")
        for source, count in summary.threats_by_source.items():
            if count > 0:
                console.print(f"  • {source.capitalize()}: {count}")
    
    # Overall summary
    if summary.total_threats > 0:
        console.print(f"\n[bold red]Total Threats: {summary.total_threats}[/bold red]")
    else:
        console.print("\n[bold green]✅ No threats detected[/bold green]")


@cli.command()
@click.option(
    "--host",
    default="0.0.0.0",
    help="Host to bind to (default: 0.0.0.0)"
)
@click.option(
    "--port",
    default=8000,
    type=int,
    help="Port to bind to (default: 8000)"
)
@click.option(
    "--reload",
    is_flag=True,
    help="Enable auto-reload on code changes (development mode)"
)
def dashboard(host: str, port: int, reload: bool):
    """Start the web dashboard.

    Launches the FastAPI web interface for monitoring threats,
    managing devices, and controlling monitors through a browser.

    Example:
        privasee dashboard
        privasee dashboard --port 3000 --reload
    """
    try:
        import uvicorn
    except ImportError:
        console.print("[red]Error: uvicorn not installed.[/red]")
        console.print("\nInstall dashboard dependencies:")
        console.print("  pip install fastapi uvicorn jinja2 python-multipart websockets")
        sys.exit(1)

    console.print(f"[green]Starting PrivaseeAI Security Dashboard...[/green]")
    console.print(f"\n[bold]Dashboard URL:[/bold] http://localhost:{port}")
    console.print(f"[bold]API Docs:[/bold] http://localhost:{port}/api/docs")
    console.print("\nPress Ctrl+C to stop\n")

    # Import and run the dashboard app
    dashboard_path = Path(__file__).parent.parent.parent / "dashboard" / "api" / "main.py"

    if not dashboard_path.exists():
        console.print(f"[red]Error: Dashboard not found at {dashboard_path}[/red]")
        console.print("\nMake sure you have the dashboard/ directory in your repository.")
        sys.exit(1)

    try:
        uvicorn.run(
            "dashboard.api.main:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped[/yellow]")


def main():
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
