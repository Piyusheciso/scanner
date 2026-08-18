"""
Web Recon Scanner - Configuration
"""

from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = BASE_DIR / "output"

LOG_DIR = BASE_DIR / "logs"


# ============================================================
# NETWORK SETTINGS
# ============================================================

DEFAULT_TIMEOUT = 10

MAX_REDIRECTS = 5

USER_AGENT = "Web-Recon-Scanner/1.0"


# ============================================================
# SCANNER INFORMATION
# ============================================================

SCANNER_NAME = "Web Recon Scanner"

SCANNER_VERSION = "1.0.0"


# ============================================================
# PHASE 3 - EXTERNAL TOOLS
# ============================================================

# ------------------------------------------------------------
# If the tools are available in Windows PATH, these names
# are sufficient.
#
# Example:
#
#     nmap.exe
#     subfinder.exe
#     whatweb
#
# If they are installed somewhere else, you can later change
# these values to full paths.
# ------------------------------------------------------------

NMAP_COMMAND = "nmap"

SUBFINDER_COMMAND = "subfinder"

WHATWEB_COMMAND = "whatweb"


# ============================================================
# PHASE 3 TOOL TIMEOUTS
# ============================================================

WHATWEB_TIMEOUT = 60

SUBFINDER_TIMEOUT = 120

NMAP_TIMEOUT = 120