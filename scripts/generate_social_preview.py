#!/usr/bin/env python3
"""
Generate social preview image for PrivaseeAI.Security repository

This script creates a 1280x640 PNG image with an architectural diagram
showing the main components of the PrivaseeAI.Security system.

Usage:
    python scripts/generate_social_preview.py [--output OUTPUT_PATH]

Requirements:
    pip install Pillow

The generated image can be uploaded to GitHub as the repository's
social preview image (Settings > Social preview).
"""

import argparse
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


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


def hex_to_rgb(hex_color):
    """Convert hex color to RGB tuple"""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))


def create_social_preview(output_path):
    """
    Create the social preview image
    
    Args:
        output_path: Path where the image will be saved
    """
    
    # Create image with dark background
    img = Image.new('RGB', (WIDTH, HEIGHT), hex_to_rgb(BG_COLOR))
    draw = ImageDraw.Draw(img)
    
    # Try to use a nice font, fallback to default
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
        subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 32)
        text_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 24)
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
    except IOError:
        # Fallback to default font
        print("Warning: DejaVu Sans font not found, using default font")
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()
        text_font = ImageFont.load_default()
        small_font = ImageFont.load_default()
    
    # Title
    title = "PrivaseeAI.Security"
    draw.text((50, 40), title, fill=hex_to_rgb(PRIMARY_COLOR), font=title_font)
    
    # Subtitle
    subtitle = "Real-Time iOS Threat Detection & Monitoring"
    draw.text((50, 130), subtitle, fill=hex_to_rgb(TEXT_COLOR), font=subtitle_font)
    
    # Architecture diagram
    y_offset = 200
    
    # Top: CLI Interface
    draw.rectangle([50, y_offset, 1230, y_offset + 60], 
                   outline=hex_to_rgb(PRIMARY_COLOR), width=3)
    draw.text((520, y_offset + 20), "CLI Interface", 
              fill=hex_to_rgb(PRIMARY_COLOR), font=text_font)
    
    # Middle: Orchestrator
    y_offset += 80
    draw.rectangle([400, y_offset, 880, y_offset + 50], 
                   outline=hex_to_rgb(SECONDARY_COLOR), width=3)
    draw.text((520, y_offset + 15), "Threat Orchestrator", 
              fill=hex_to_rgb(SECONDARY_COLOR), font=text_font)
    
    # Bottom: Monitors (4 boxes)
    y_offset += 70
    box_width = 250
    box_height = 60
    spacing = 50
    
    monitors = [
        ("VPN\nIntegrity", PRIMARY_COLOR),
        ("API\nAbuse", PURPLE_COLOR),
        ("Carrier\nCompromise", ACCENT_COLOR),
        ("Backup\nMonitor", SECONDARY_COLOR)
    ]
    
    x_start = 80
    for i, (monitor, color) in enumerate(monitors):
        x = x_start + i * (box_width + spacing)
        draw.rectangle([x, y_offset, x + box_width, y_offset + box_height], 
                      outline=hex_to_rgb(color), width=3)
        lines = monitor.split('\n')
        for j, line in enumerate(lines):
            draw.text((x + 60, y_offset + 10 + j * 25), line, 
                     fill=hex_to_rgb(color), font=small_font)
    
    # Alert system at bottom
    y_offset += 90
    draw.rectangle([400, y_offset, 880, y_offset + 50], 
                   outline=hex_to_rgb(ACCENT_COLOR), width=3)
    draw.text((520, y_offset + 15), "Telegram Alerter", 
              fill=hex_to_rgb(ACCENT_COLOR), font=text_font)
    
    # Add arrows/connections (simplified)
    # Arrow from CLI to Orchestrator
    draw.line([(640, 260), (640, 280)], fill=hex_to_rgb(TEXT_COLOR), width=2)
    
    # Arrows from Orchestrator to monitors
    orch_center_x = 640
    orch_y = 330
    monitor_y = 350
    
    for i in range(4):
        monitor_x = x_start + box_width // 2 + i * (box_width + spacing)
        draw.line([(orch_center_x, orch_y), (monitor_x, monitor_y)], 
                 fill=hex_to_rgb(TEXT_COLOR), width=2)
    
    # Arrows from monitors to alerter
    alert_y = 510
    for i in range(4):
        monitor_x = x_start + box_width // 2 + i * (box_width + spacing)
        draw.line([(monitor_x, y_offset - 30), (640, alert_y)], 
                 fill=hex_to_rgb(TEXT_COLOR), width=2)
    
    # Footer with key features
    y_offset = 580
    features = "🛡️ Battle-Tested  •  🔒 Privacy-First  •  ⚡ Real-Time  •  ✅ 196 Tests"
    draw.text((180, y_offset), features, fill=hex_to_rgb(TEXT_COLOR), font=small_font)
    
    # Save the image
    img.save(output_path)
    print(f"Social preview image created: {output_path}")
    print(f"Dimensions: {WIDTH}x{HEIGHT}")
    print(f"File size: {Path(output_path).stat().st_size / 1024:.1f} KB")


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
