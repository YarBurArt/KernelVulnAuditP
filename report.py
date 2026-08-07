"""Entry point for report generation.

Kept as a thin top-level shim so the historical CLI/Streamlit entry points
(``python report.py``, ``streamlit run report.py``, ``import report``) keep
working after the logic moved into the ``report`` package.
"""

import sys

from report import STREAMLIT_AVAILABLE, main, main_cli

if __name__ == "__main__":
    if STREAMLIT_AVAILABLE and len(sys.argv) == 1:
        main()
    else:
        main_cli()