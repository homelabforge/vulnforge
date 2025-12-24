#!/usr/bin/env python3
"""
Analyze codebase for common CodeQL security patterns that likely triggered the 55 alerts.
Based on common Python and JavaScript security issues.
"""

import os
import re
from pathlib import Path
from collections import defaultdict

# Common CodeQL patterns to look for
PATTERNS = {
    "python": {
        "sql_injection": [
            r"\.execute\([^?]*\+",  # String concatenation in execute
            r"\.execute\(f['\"]",   # f-string in execute
            r"\.execute\(.*%"       # % formatting in execute
        ],
        "command_injection": [
            r"subprocess\.(run|call|Popen)\(.*shell=True",
            r"os\.system\(",
            r"os\.popen\("
        ],
        "path_traversal": [
            r"open\([^)]*\+",  # String concatenation with open()
            r"Path\([^)]*\+"   # String concatenation with Path()
        ],
        "hardcoded_credentials": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]"
        ],
        "weak_crypto": [
            r"hashlib\.(md5|sha1)\(",
            r"Random\(\)",
            r"random\.random\("
        ],
        "xxe": [
            r"etree\.XMLParser\(",
            r"xml\.etree",
        ],
        "deserialize_untrusted": [
            r"pickle\.loads?\(",
            r"yaml\.load\([^,]*\)",  # yaml.load without SafeLoader
        ]
    },
    "javascript": {
        "xss": [
            r"innerHTML\s*=",
            r"dangerouslySetInnerHTML",
            r"document\.write\("
        ],
        "prototype_pollution": [
            r"Object\.assign\(",
            r"\[.*\]\s*="  # Bracket notation assignment
        ],
        "insecure_random": [
            r"Math\.random\(\)"
        ],
        "eval": [
            r"\beval\(",
            r"Function\(['\"]"
        ],
        "regex_dos": [
            r"new RegExp\([^)]*\+",  # Dynamic regex construction
        ]
    }
}

def scan_file(filepath, language):
    """Scan a file for security patterns."""
    findings = defaultdict(list)
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            for category, patterns in PATTERNS[language].items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings[category].append({
                            'file': str(filepath),
                            'line': line_num,
                            'code': line.strip()
                        })
    except Exception as e:
        pass
    
    return findings

def main():
    print("=== CodeQL-style Security Pattern Analysis ===\n")
    
    # Scan Python backend
    backend_findings = defaultdict(list)
    backend_path = Path('backend/app')
    if backend_path.exists():
        for py_file in backend_path.rglob('*.py'):
            file_findings = scan_file(py_file, 'python')
            for category, items in file_findings.items():
                backend_findings[category].extend(items)
    
    # Scan JavaScript frontend
    frontend_findings = defaultdict(list)
    frontend_path = Path('frontend/src')
    if frontend_path.exists():
        for js_file in frontend_path.rglob('*.{ts,tsx,js,jsx}'):
            if js_file.suffix in ['.ts', '.tsx', '.js', '.jsx']:
                file_findings = scan_file(js_file, 'javascript')
                for category, items in file_findings.items():
                    frontend_findings[category].extend(items)
    
    # Print Python findings
    print("### Python Backend Findings ###")
    total_python = 0
    for category, findings in sorted(backend_findings.items()):
        if findings:
            print(f"\n{category.upper().replace('_', ' ')}: {len(findings)} occurrences")
            total_python += len(findings)
            for finding in findings[:3]:  # Show first 3
                print(f"  {finding['file']}:{finding['line']}")
                print(f"    {finding['code'][:80]}")
            if len(findings) > 3:
                print(f"  ... and {len(findings) - 3} more")
    
    print(f"\nTotal Python issues: {total_python}")
    
    # Print JavaScript findings
    print("\n### JavaScript/TypeScript Frontend Findings ###")
    total_js = 0
    for category, findings in sorted(frontend_findings.items()):
        if findings:
            print(f"\n{category.upper().replace('_', ' ')}: {len(findings)} occurrences")
            total_js += len(findings)
            for finding in findings[:3]:
                print(f"  {finding['file']}:{finding['line']}")
                print(f"    {finding['code'][:80]}")
            if len(findings) > 3:
                print(f"  ... and {len(findings) - 3} more")
    
    print(f"\nTotal JavaScript issues: {total_js}")
    print(f"\n=== GRAND TOTAL: {total_python + total_js} potential issues ===")

if __name__ == '__main__':
    main()
