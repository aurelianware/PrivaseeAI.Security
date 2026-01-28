#!/bin/bash

# Usage: ./setup_telegram.sh <bot_token> <chat_id>
# Example: ./setup_telegram.sh "8433178793:AAGXrcnw..." "8492117930"

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <TELEGRAM_BOT_TOKEN> <TELEGRAM_CHAT_ID>"
    echo ""
    echo "Example:"
    echo "  $0 \"8433178793:AAGXrcnw94Ya0vOr5_2F_mFUWwNWiqWbo_4\" \"8492117930\""
    echo ""
    echo "To get your chat ID:"
    echo "  1. Message your bot in Telegram"
    echo "  2. Visit: https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates"
    echo "  3. Look for 'chat':{'id': YOUR_CHAT_ID}"
    exit 1
fi

BOT_TOKEN="$1"
CHAT_ID="$2"

# Add Telegram configuration to ~/.zshrc
echo "" >> ~/.zshrc
echo "# Telegram Bot Configuration for PrivaseeAI" >> ~/.zshrc
echo "export TELEGRAM_BOT_TOKEN=\"$BOT_TOKEN\"" >> ~/.zshrc
echo "export TELEGRAM_CHAT_ID=\"$CHAT_ID\"" >> ~/.zshrc

echo "✅ Telegram credentials saved to ~/.zshrc"
echo ""
echo "Run the following to activate in current terminal:"
echo "  source ~/.zshrc"
echo ""
echo "Then verify with:"
echo "  privasee config"
