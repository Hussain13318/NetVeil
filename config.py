"""NetVeil API key configuration.

Priority:
1) Environment variables (recommended for GitHub safety)
2) Hardcoded fallback values below
"""

import os

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "YOUR_SHODAN_API_KEY_HERE")
