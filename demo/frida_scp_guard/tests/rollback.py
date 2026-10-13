"""Remove this newly added demo directory after validating its fixed location."""
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
if root.name != "frida_scp_guard" or root.parent.name != "demo":
    raise SystemExit(f"unexpected rollback target: {root}")
shutil.rmtree(root)
print(f"removed {root}")
