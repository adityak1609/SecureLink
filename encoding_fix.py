# ==============================================================================
# encoding_fix.py — Windows Console Encoding Fix
# ==============================================================================
#
# Windows consoles default to cp1252 which cannot display Unicode box-drawing
# characters. This module reconfigures stdout/stderr to use UTF-8.
#
# Import this at the top of any script that prints Unicode characters.
# ==============================================================================

import sys
import os

# Enable ANSI escape codes on Windows 10+
if sys.platform == "win32":
    os.system("")  # Enables ANSI escape processing

# Reconfigure stdout/stderr to UTF-8 if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
