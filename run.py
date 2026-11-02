"""CyberSentinel: Universal Entry Point.

Usage:
    python run.py web                          # Start the web dashboard (port 5000)
    python run.py scan <target_url> [options]  # Run a CLI scan directly
"""

import sys
import uvicorn
from core.orchestrator import main as cli_main


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return

    command = sys.argv[1].lower()

    if command == "web":
        print("[+] Starting CyberSentinel Web Dashboard on http://127.0.0.1:5000")
        uvicorn.run("web.app:app", host="0.0.0.0", port=5000, reload=False)
    elif command == "scan":
        # Pass remaining arguments to orchestrator CLI
        cli_main(sys.argv[2:])
    else:
        # Default fallback: treat all args as CLI scan args
        cli_main(sys.argv[1:])


if __name__ == "__main__":
    main()
