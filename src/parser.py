import re
from typing import Optional

BASE_RE = re.compile(
    r"^\s*FROM\s+([^\s:@]+(?:/[^\s:@]+)*)(?::([^\s@]+))?",
    re.IGNORECASE
)

def find_base_image(text: str) -> tuple[Optional[str], Optional[str]]:
    for line in text.splitlines():
        m = BASE_RE.match(line)
        if m:
            return m.group(1), (m.group(2) or "latest")
    return None, None

def replace_base_image(text: str, new_image: str) -> str:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().upper().startswith("FROM "):
            idx = line.lower().find(" as ")
            alias = line[idx:] if idx != -1 else ""
            lines[i] = f"FROM {new_image}{alias}"
            return "\n".join(lines)
    return text
