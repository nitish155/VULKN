import re

# ── Load spaCy model at startup ────────────────────────────────────────
nlp = None

def load_nlp():
    
    global nlp
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        print("[nlp_analyzer] spaCy model loaded: en_core_web_sm")
        return True
    except OSError:
        print("[nlp_analyzer] WARNING: en_core_web_sm not found")
        print("[nlp_analyzer] Run: python -m spacy download en_core_web_sm")
        return False
    except ImportError:
        print("[nlp_analyzer] WARNING: spaCy not installed")
        print("[nlp_analyzer] Run: pip install spacy")
        return False

load_nlp()

# ── Security-specific regex patterns ──────────────────────────────────
# spaCy handles general NER; regex handles security patterns

DB_NAME_PATTERNS = [
    r'\bmysql\b', r'\bpostgresql\b', r'\bpostgres\b', r'\bsqlite\b',
    r'\boracle\b', r'\bmssql\b', r'\bsql server\b', r'\bmongodb\b',
    r'\bredis\b', r'\bmariadb\b',
]

FILE_PATH_PATTERNS = [
    r'/etc/passwd', r'/etc/shadow', r'/etc/hosts',
    r'/var/www/[^\s<>\'"]+',
    r'/home/\w+/[^\s<>\'"\]]+',
    r'/usr/[^\s<>\'"]+',
    r'/tmp/[^\s<>\'"]+',
    r'C:\\\\[A-Za-z\\\\]+',
]

STACK_TRACE_PATTERNS = [
    r'(?:Fatal error|Warning|Notice|Parse error):[^\n]+on line \d+',
    r'Traceback \(most recent call last\)',
    r'Exception in thread "[^"]*"',
    r'at [a-zA-Z_$][a-zA-Z0-9_$.]*\([^)]+\)',
    r'caused by:[^\n]+',
    r'#\d+ [^\n]+\([^\n]+\)',
]

VERSION_STRING_PATTERNS = [
    r'PHP/[\d.]+(?:[-+]\w+)?',
    r'Apache/[\d.]+',
    r'nginx/[\d.]+',
    r'Python/[\d.]+',
    r'OpenSSL/[\w.]+',
    r'MySQL/[\d.]+',
]


def extract_entities(text: str) -> dict:
    
    text_lower = text.lower()
    results = {
        "database_names":  [],
        "file_paths":      [],
        "stack_traces":    [],
        "version_strings": [],
        "spacy_entities":  [],
        "risk_level":      "Low",
        "summary":         ""
    }

    # 1. Database names (regex)
    for pattern in DB_NAME_PATTERNS:
        matches = re.findall(pattern, text_lower)
        results["database_names"].extend(matches)
    results["database_names"] = list(set(results["database_names"]))

    # 2. File paths (regex)
    for pattern in FILE_PATH_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        results["file_paths"].extend(matches)
    results["file_paths"] = list(set(results["file_paths"]))

    # 3. Stack trace patterns (regex)
    for pattern in STACK_TRACE_PATTERNS:
        matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        results["stack_traces"].extend([m[:150] for m in matches])
    results["stack_traces"] = list(set(results["stack_traces"]))

    # 4. Version strings (regex)
    for pattern in VERSION_STRING_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        results["version_strings"].extend(matches)
    results["version_strings"] = list(set(results["version_strings"]))

    # 5. spaCy NER (general entities — organisations, products)
    if nlp is not None:
        doc = nlp(text[:5000])  # limit to 5000 chars for performance
        for ent in doc.ents:
            if ent.label_ in ("ORG", "PRODUCT", "GPE", "LOC"):
                results["spacy_entities"].append({
                    "text":  ent.text,
                    "label": ent.label_
                })

    # 6. Risk level based on how much was leaked
    leak_count = (
        len(results["database_names"]) +
        len(results["file_paths"]) +
        len(results["stack_traces"]) +
        len(results["version_strings"])
    )
    if leak_count >= 4 or "/etc/passwd" in text:
        results["risk_level"] = "High"
    elif leak_count >= 2:
        results["risk_level"] = "Medium"
    elif leak_count >= 1:
        results["risk_level"] = "Low"

    # 7. Build human-readable summary
    parts = []
    if results["database_names"]:
        parts.append(f"DB: {', '.join(results['database_names'][:3])}")
    if results["file_paths"]:
        parts.append(f"Files: {len(results['file_paths'])} path(s)")
    if results["stack_traces"]:
        parts.append("Stack trace exposed")
    if results["version_strings"]:
        parts.append(f"Versions: {', '.join(results['version_strings'][:2])}")

    results["summary"] = " | ".join(parts) if parts else "No sensitive info detected"

    return results


# ── Test: run this file directly ───────────────────────────────────────
if __name__ == "__main__":

    test_cases = [
        {
            "name": "SQL injection error (high risk)",
            "text": (
                "Fatal error: mysql_fetch_array() expects parameter 1 to be resource\n"
                "in /var/www/html/login.php on line 42\n"
                "Warning: mysql_connect() in /var/www/html/db.php on line 8\n"
                "Stack trace:\n"
                "  #0 /var/www/html/login.php(42): mysql_fetch_array()\n"
                "Server: Apache/2.4.41 (Ubuntu) PHP/7.4.3"
            )
        },
        {
            "name": "XSS reflected (low risk)",
            "text": " reflected in search results"
        },
        {
            "name": "Normal safe response",
            "text": "Invalid credentials. Please try again."
        },
    ]

    print("=" * 60)
    print("TESTING ai_service/nlp_analyzer.py")
    print("=" * 60)

    for tc in test_cases:
        result = extract_entities(tc["text"])
        print(f"\n  [{result['risk_level']:6s}] {tc['name']}")
        print(f"          Summary  : {result['summary']}")
        print(f"          DB names : {result['database_names']}")
        print(f"          Files    : {result['file_paths'][:3]}")
        print(f"          Traces   : {len(result['stack_traces'])} found")
        print(f"          Versions : {result['version_strings']}")