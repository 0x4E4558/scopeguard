"""
app.py
~~~~~~
Entry point for ScopeGuard.

  python app.py

Opens on http://127.0.0.1:5000
All data is stored locally in ./data/scopeguard.db
No network connections are made.
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from app import create_app

if __name__ == "__main__":
    application = create_app()
    debug = os.environ.get("SCOPEGUARD_DEBUG", "false").lower() in ("1", "true", "yes")
    print("\n" + "─" * 52)
    print("  ScopeGuard")
    print("  http://127.0.0.1:5000")
    print("  Local only · No network calls")
    print("  Data: ./data/scopeguard.db")
    print("─" * 52 + "\n")
    application.run(debug=debug, port=5000, host="127.0.0.1")
