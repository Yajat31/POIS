"""
check_imports.py — Static check to enforce the no-library rule.

Scans all .py files under src/ and raises an error if any forbidden
cryptographic library is imported.

Run: python tests/check_imports.py
"""

import os
import sys
import ast
import re

FORBIDDEN = [
    "Crypto", "cryptography", "OpenSSL", "rsa",
    "nacl", "jose", "pycryptodome", "pycryptodomex",
    "pyOpenSSL", "paramiko.crypto",
]

# hashlib is allowed for non-HMAC use (e.g., sha256 in utilities),
# but explicitly forbidden for HMAC substitution in PA#10 logic.
FORBIDDEN_PATTERNS = [
    r"import\s+hashlib\s*;?\s*hmac",
    r"from\s+Crypto",
    r"import\s+Crypto",
    r"from\s+cryptography",
    r"import\s+cryptography",
    r"import\s+rsa\b",
    r"from\s+rsa\b",
    r"import\s+nacl",
    r"from\s+nacl",
    r"import\s+jose",
    r"from\s+jose",
    r"import\s+OpenSSL",
    r"from\s+OpenSSL",
]


def check_file(filepath: str) -> list[str]:
    """Check a single Python file for forbidden imports."""
    violations = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return violations

    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            violations.append(f"{filepath}: matches forbidden pattern '{pattern}'")

    # Also AST-parse to catch aliased imports
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                else:
                    names = [node.module or ""]
                for name in names:
                    for forbidden in FORBIDDEN:
                        if name == forbidden or name.startswith(forbidden + "."):
                            violations.append(
                                f"{filepath}:{node.lineno}: forbidden import of '{name}'"
                            )
    except SyntaxError:
        pass

    return violations


def main():
    src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
    src_dir = os.path.abspath(src_dir)

    all_violations = []
    for root, dirs, files in os.walk(src_dir):
        for filename in files:
            if filename.endswith(".py"):
                filepath = os.path.join(root, filename)
                violations = check_file(filepath)
                all_violations.extend(violations)

    if all_violations:
        print("❌ FORBIDDEN LIBRARY IMPORTS DETECTED:")
        for v in all_violations:
            print(f"  {v}")
        sys.exit(1)
    else:
        print(f"✅ No forbidden imports found in {src_dir}")
        sys.exit(0)


if __name__ == "__main__":
    main()
