#!/usr/bin/env python3
"""
Generate social preview image for PrivaseeAI.Security repository

This script creates a 1280x640 PNG image with an architectural diagram
showing the main components of the PrivaseeAI.Security system.

This is a development/maintenance utility and requires the Pillow
library (PIL), which is not installed by default.

Install with:
    pip install Pillow

Usage:
    python scripts/generate_social_preview.py [--output OUTPUT_PATH]

The generated image can be uploaded to GitHub as the repository's
social preview image (Settings > Social preview).
"""

import argparse
from pathlib import Path
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as exc:
    sys.stderr.write(
        "Error: The Pillow library (PIL) is required to run this script.\n"
        "Install it with:\n"
        "    pip install Pillow\n"
    )
    raise SystemExit(1) from exc


# Image dimensions (GitHub recommended: 1280x640)
WIDTH = 1280
HEIGHT = 640

# Color scheme - Security/Privacy theme (GitHub dark colors)
BG_COLOR = "#0D1117"  # GitHub dark background
PRIMARY_COLOR = "#58A6FF"  # GitHub blue
SECONDARY_COLOR = "#7EE787"  # GitHub green
TEXT_COLOR = "#C9D1D9"  # GitHub text
ACCENT_COLOR = "#F85149"  # GitHub red (for alerts/threats)
PURPLE_COLOR = "#BC8CFF"  # GitHub purple

# Layout constants - extracted for maintainability
# Margins and positions
MARGIN_LEFT = 50
TITLE_Y = 40
SUBTITLE_Y = 130

# CLI Interface box
CLI_Y = 200
CLI_RIGHT = 1230
CLI_HEIGHT = 60
CLI_TEXT_X = 520
CLI_TEXT_Y_OFFSET = 20

# Orchestrator box
ORCH_Y_SPACING = 80
ORCH_LEFT = 400
ORCH_RIGHT = 880
ORCH_HEIGHT = 50
ORCH_TEXT_X = 520
ORCH_TEXT_Y_OFFSET = 15
ORCH_CENTER_X = 640
ORCH_ARROW_Y = 330

# Monitor boxes
MONITOR_Y_SPACING = 70
MONITOR_BOX_WIDTH = 250
MONITOR_BOX_HEIGHT = 60
MONITOR_SPACING = 50
MONITOR_X_START = 80
MONITOR_TEXT_X_OFFSET = 60
MONITOR_TEXT_Y_OFFSET = 10
MONITOR_TEXT_LINE_HEIGHT = 25
MONITOR_ARROW_Y = 350

# Alerter box
ALERTER_Y_SPACING = 90
ALERTER_LEFT = 400
ALERTER_RIGHT = 880
ALERTER_HEIGHT = 50
ALERTER_TEXT_X = 520
ALERTER_TEXT_Y_OFFSET = 15
ALERTER_ARROW_Y = 510
ALERTER_ARROW_Y_OFFSET = 30

# Footer
FOOTER_Y = 580
FOOTER_X = 180

# Arrow constants
CLI_ORCH_ARROW_START_Y = 260
CLI_ORCH_ARROW_END_Y = 280
ARROW_WIDTH = 2

# Box border width
BOX_BORDER_WIDTH = 3

# Font sizes
TITLE_FONT_SIZE = 72
SUBTITLE_FONT_SIZE = 32
TEXT_FONT_SIZE = 24
SMALL_FONT_SIZE = 20

# Common font paths across different operating systems
FONT_PATHS = [
    # Linux
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    # macOS
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/Library/Fonts/Arial Bold.ttf",
    "/Library/Fonts/Arial.ttf",
    # Windows (via Wine or WSL)
    "C:\\Windows\\Fonts\\arialbd.ttf",
    "C:\\Windows\\Fonts\\arial.ttf",
]


def hex_to_rgb(hex_color):
    """Convert hex color to RGB tuple"""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))


def find_font(font_paths, size):
    """
    Try to find a working font from a list of paths.
    
    Args:
        font_paths: List of font file paths to try
        size: Font size
        
    Returns:
        ImageFont object (truetype if found, default otherwise)
    """
    for font_path in font_paths:
        try:
            return ImageFont.truetype(font_path, size)
        except (IOError, OSError):
            continue
    
    # No fonts found, return default
    sys.stderr.write("Warning: Could not find fonts at standard locations, using default font\n")
    return ImageFont.load_default()


def create_social_preview(output_path):
    """
    Create the social preview image
    
    Args:
        output_path: Path where the image will be saved
    """
    
    # Create image with dark background
    img = Image.new('RGB', (WIDTH, HEIGHT), hex_to_rgb(BG_COLOR))
    draw = ImageDraw.Draw(img)
    
    # Load fonts with cross-platform support
    # Try bold fonts first for title
    bold_font_paths = [p for p in FONT_PATHS if 'Bold' in p or 'bold' in p]
    regular_font_paths = [p for p in FONT_PATHS if 'Bold' not in p and 'bold' not in p]
    
    title_font = find_font(bold_font_paths, TITLE_FONT_SIZE)
    subtitle_font = find_font(regular_font_paths, SUBTITLE_FONT_SIZE)
    text_font = find_font(regular_font_paths, TEXT_FONT_SIZE)
    small_font = find_font(regular_font_paths, SMALL_FONT_SIZE)
    
    # Title
    title = "PrivaseeAI.Security"
    draw.text((MARGIN_LEFT, TITLE_Y), title, fill=hex_to_rgb(PRIMARY_COLOR), font=title_font)
    
    # Subtitle
    subtitle = "Real-Time iOS Threat Detection & Monitoring"
    draw.text((MARGIN_LEFT, SUBTITLE_Y), subtitle, fill=hex_to_rgb(TEXT_COLOR), font=subtitle_font)
    
    # Architecture diagram
    y_offset = CLI_Y
    
    # Top: CLI Interface
    draw.rectangle([MARGIN_LEFT, y_offset, CLI_RIGHT, y_offset + CLI_HEIGHT], 
                   outline=hex_to_rgb(PRIMARY_COLOR), width=BOX_BORDER_WIDTH)
    draw.text((CLI_TEXT_X, y_offset + CLI_TEXT_Y_OFFSET), "CLI Interface", 
              fill=hex_to_rgb(PRIMARY_COLOR), font=text_font)
    
    # Middle: Orchestrator
    y_offset += ORCH_Y_SPACING
    draw.rectangle([ORCH_LEFT, y_offset, ORCH_RIGHT, y_offset + ORCH_HEIGHT], 
                   outline=hex_to_rgb(SECONDARY_COLOR), width=BOX_BORDER_WIDTH)
    draw.text((ORCH_TEXT_X, y_offset + ORCH_TEXT_Y_OFFSET), "Threat Orchestrator", 
              fill=hex_to_rgb(SECONDARY_COLOR), font=text_font)
    
    # Bottom: Monitors (4 boxes)
    y_offset += MONITOR_Y_SPACING
    
    monitors = [
        ("VPN\nIntegrity", PRIMARY_COLOR),
        ("API\nAbuse", PURPLE_COLOR),
        ("Carrier\nCompromise", ACCENT_COLOR),
        ("Backup\nMonitor", SECONDARY_COLOR)
    ]
    
    for i, (monitor, color) in enumerate(monitors):
        x = MONITOR_X_START + i * (MONITOR_BOX_WIDTH + MONITOR_SPACING)
        draw.rectangle([x, y_offset, x + MONITOR_BOX_WIDTH, y_offset + MONITOR_BOX_HEIGHT], 
                      outline=hex_to_rgb(color), width=BOX_BORDER_WIDTH)
        lines = monitor.split('\n')
        for j, line in enumerate(lines):
            draw.text((x + MONITOR_TEXT_X_OFFSET, y_offset + MONITOR_TEXT_Y_OFFSET + j * MONITOR_TEXT_LINE_HEIGHT), 
                     line, fill=hex_to_rgb(color), font=small_font)
    
    # Alert system at bottom
    y_offset += ALERTER_Y_SPACING
    draw.rectangle([ALERTER_LEFT, y_offset, ALERTER_RIGHT, y_offset + ALERTER_HEIGHT], 
                   outline=hex_to_rgb(ACCENT_COLOR), width=BOX_BORDER_WIDTH)
    draw.text((ALERTER_TEXT_X, y_offset + ALERTER_TEXT_Y_OFFSET), "Telegram Alerter", 
              fill=hex_to_rgb(ACCENT_COLOR), font=text_font)
    
    # Add arrows/connections (simplified)
    # Arrow from CLI to Orchestrator
    draw.line([(ORCH_CENTER_X, CLI_ORCH_ARROW_START_Y), (ORCH_CENTER_X, CLI_ORCH_ARROW_END_Y)], 
             fill=hex_to_rgb(TEXT_COLOR), width=ARROW_WIDTH)
    
    # Arrows from Orchestrator to monitors
    for i in range(4):
        monitor_x = MONITOR_X_START + MONITOR_BOX_WIDTH // 2 + i * (MONITOR_BOX_WIDTH + MONITOR_SPACING)
        draw.line([(ORCH_CENTER_X, ORCH_ARROW_Y), (monitor_x, MONITOR_ARROW_Y)], 
                 fill=hex_to_rgb(TEXT_COLOR), width=ARROW_WIDTH)
    
    # Arrows from monitors to alerter
    for i in range(4):
        monitor_x = MONITOR_X_START + MONITOR_BOX_WIDTH // 2 + i * (MONITOR_BOX_WIDTH + MONITOR_SPACING)
        draw.line([(monitor_x, y_offset - ALERTER_ARROW_Y_OFFSET), (ORCH_CENTER_X, ALERTER_ARROW_Y)], 
                 fill=hex_to_rgb(TEXT_COLOR), width=ARROW_WIDTH)
    
    # Footer with key features
    features = "🛡️ Battle-Tested  •  🔒 Privacy-First  •  ⚡ Real-Time  •  ✅ 196 Tests"
    draw.text((FOOTER_X, FOOTER_Y), features, fill=hex_to_rgb(TEXT_COLOR), font=small_font)
    
    # Save the image with error handling
    try:
        img.save(output_path)
    except OSError as e:
        sys.stderr.write(f"Error: Failed to save image to '{output_path}': {e}\n")
        sys.exit(1)

    # Try to determine file size; if it fails, continue without it
    try:
        file_size_kb = Path(output_path).stat().st_size / 1024
    except OSError as e:
        sys.stderr.write(f"Warning: Image saved but failed to retrieve file size for '{output_path}': {e}\n")
        file_size_kb = None

    print(f"Social preview image created: {output_path}")
    print(f"Dimensions: {WIDTH}x{HEIGHT}")
    if file_size_kb is not None:
        print(f"File size: {file_size_kb:.1f} KB")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Generate social preview image for PrivaseeAI.Security repository'
    )
    parser.add_argument(
        '--output',
        default='.github/assets/social-preview.png',
        help='Output path for the generated image (default: .github/assets/social-preview.png)'
    )
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Generate the image
    create_social_preview(str(output_path))
    
    print("\nNext steps:")
    print("1. Review the generated image")
    print("2. Go to GitHub repository Settings > Social preview")
    print("3. Upload the image")
    print("4. See .github/SOCIAL_PREVIEW_SETUP.md for detailed instructions")


if __name__ == '__main__':
    main()
