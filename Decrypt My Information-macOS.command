#!/bin/bash
# ---------------------------------------------------------------------
#  Launcher for whoever needs to open the encrypted document.
#
#  Named .command rather than .sh so macOS will run it on a double-click
#  in Finder; a .sh opens in a text editor instead, which is what a
#  beneficiary would have met before.
#
#  It also no longer depends on a .venv that nothing in this repository
#  creates -- that activation failed on every fresh copy, and the script
#  carried on regardless into a `python` that may not exist.
# ---------------------------------------------------------------------
set -u

cd "$(dirname "$0")" || exit 1

PYTHON=""
if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>/dev/null; then
    PYTHON="python"
fi

if [ -z "$PYTHON" ]; then
    cat <<'MESSAGE'

  This computer does not have Python 3 installed, and this program
  needs it.

  On macOS, the simplest route is:

    1. Open the Terminal application.
    2. Type this and press Return:   xcode-select --install
    3. When it finishes, run this program again.

  Or download an installer from https://www.python.org/downloads/

  Nothing has been damaged. Your encrypted document is untouched.

MESSAGE
    read -r -p "Press Return to close this window..." _
    exit 1
fi

"$PYTHON" "internals/scripts/decrypt.py" "$@"
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
    echo
    echo "  The program stopped without finishing. The message above explains why."
    echo
    read -r -p "Press Return to close this window..." _
fi
exit "$STATUS"
