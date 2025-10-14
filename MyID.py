import EncodeID
from pathlib import Path
import subprocess

def _encode_from_text(text: str):
    txt = text.strip()
    if txt.endswith(".onion"):
        txt = txt[:-6]
    return EncodeID.encode_id(txt)

def id(ishere: str):

    path = Path(ishere) / "hostname"

    try:
        with path.open("r", encoding="utf-8") as f:
            return _encode_from_text(f.read())
    except FileNotFoundError:
        return False
    except PermissionError:
        pass
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["cat", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode == 0 and proc.stdout:
            return _encode_from_text(proc.stdout)
        else:
            return False
    except Exception:
        return False
