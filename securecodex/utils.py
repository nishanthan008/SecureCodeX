"""
Utility functions for CLI
"""
import sys
import os

def safe_print(message):
    """
    Print message safely, handling Unicode errors on Windows
    """
    try:
        print(message)
    except UnicodeEncodeError:
        # Fallback for Windows console that doesn't support Unicode
        # Replace emojis with ASCII equivalents
        replacements = {
            '📁': '[FILES]',
            '📄': '[REPORT]',
            '✅': '[OK]',
            '❌': '[ERROR]',
            '⚠️': '[WARNING]',
            '💾': '[SAVE]',
            '📊': '[SUMMARY]',
            '🔴': '[CRITICAL]',
            '🟠': '[HIGH]',
            '🟡': '[MEDIUM]',
            '🟢': '[LOW]',
            'ℹ️': '[INFO]',
            '📋': '[TOTAL]',
            '📝': '[NOTE]'
        }
        
        for emoji, replacement in replacements.items():
            message = message.replace(emoji, replacement)
        
        print(message)

def get_console_width():
    """Get console width, default to 80 if unable to determine"""
    try:
        return os.get_terminal_size().columns
    except:
        return 80
