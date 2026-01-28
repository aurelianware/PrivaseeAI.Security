#!/bin/bash
# Quick Install & Test Script for MVP Orchestrator

set -e

echo "🚀 PrivaseeAI Security - MVP Orchestrator Setup"
echo "=============================================="

# Check Python version
echo "Checking Python version..."
python3 --version || { echo "❌ Python 3 required"; exit 1; }

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install click rich PyYAML || { echo "❌ Failed to install dependencies"; exit 1; }

# Install in development mode
echo ""
echo "🔧 Installing privaseeai-security..."
pip3 install -e . || { echo "❌ Failed to install package"; exit 1; }

echo ""
echo "✅ Installation complete!"
echo ""
echo "Available commands:"
echo "  privasee config  - Show configuration"
echo "  privasee scan    - Run one-time scan"
echo "  privasee start   - Start continuous monitoring"
echo ""
echo "Try running: privasee config"
