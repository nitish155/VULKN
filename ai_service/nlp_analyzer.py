import re

# ---------------------------------------------------------------------
# Load the spaCy model once, when this module is imported
# ---------------------------------------------------------------------
nlp = None


def load_nlp():
    """Load spaCy en_core_web_sm. Falls back gracefully if it is not installed."""
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
    r'\b[A-Za-z]:\\(?:[\w.\-]+\\)*[\w.\-]*',      
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
        "database_names": [],
        "file_paths": [],
        "stack_traces": [],
        "version_strings": [],
        "spacy_entities": [],
        "risk_level": "Low",
        "summary": "",
    }

    for pattern in DB_NAME_PATTERNS:
        results["database_names"].extend(re.findall(pattern, text_lower))
    results["database_names"] = list(set(results["database_names"]))

    for pattern in FILE_PATH_PATTERNS:
        results["file_paths"].extend(re.findall(pattern, text, re.IGNORECASE))
    results["file_paths"] = list(set(results["file_paths"]))

    for pattern in STACK_TRACE_PATTERNS:
        matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        results["stack_traces"].extend([m[:150] for m in matches])
    results["stack_traces"] = list(set(results["stack_traces"]))

    for pattern in VERSION_STRING_PATTERNS:
        results["version_strings"].extend(re.findall(pattern, text, re.IGNORECASE))
    results["version_strings"] = list(set(results["version_strings"]))

    if nlp is not None:
        doc = nlp(text[:5000])
        for ent in doc.ents:
            if ent.label_ in ("ORG", "PRODUCT", "GPE", "LOC"):
                results["spacy_entities"].append({"text": ent.text, "label": ent.label_})

    leak_count = (len(results["database_names"]) + len(results["file_paths"]) +
                  len(results["stack_traces"]) + len(results["version_strings"]))
    if leak_count >= 4 or "/etc/passwd" in text:
        results["risk_level"] = "High"
    elif leak_count >= 2:
        results["risk_level"] = "Medium"
    elif leak_count >= 1:
        results["risk_level"] = "Low"

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




SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
MAX_TEXT_CHARS = 200_000   # safety limit: never scan more than this many characters
MAX_VALUE_CHARS = 150      # shorten very long matched values
MAX_PER_TYPE = 5           # at most 5 items of one type (a 40-line stack trace is not 40 items)

_I = re.IGNORECASE
_TAGS = re.compile(r"<[^>]*>")   # used to remove HTML tags such as <b>Warning</b> before matching

# (technology, regex). Every match becomes a "database_error" item (severity High).
DB_ERROR_RULES = [
    ("MySQL",                  re.compile(r"you have an error in your sql syntax[^\n]{0,60}", _I)),
    ("MySQL",                  re.compile(r"\bmysqli?_[a-z_]+\(\)", _I)),
    ("MySQL",                  re.compile(r"\bmysqli?\s+error\b[^\n]{0,50}", _I)),
    ("Oracle",                 re.compile(r"\bORA-\d{5}\b(?::[^\n.]{0,80})?", _I)),
    ("SQL standard (SQLSTATE)", re.compile(r"\bSQLSTATE\b(?:\[[0-9A-Za-z]+\])?[^\n]{0,60}", _I)),
    ("PostgreSQL",             re.compile(r"\bpg_query\(\)|PostgreSQL query failed|\bpsycopg2\.\w+Error", _I)),
    ("Microsoft SQL Server",   re.compile(r"Microsoft OLE DB Provider[^\n]{0,40}"
                                          r"|Unclosed quotation mark after the character string"
                                          r"|\bODBC (?:SQL Server )?Driver[^\n]{0,40}", _I)),
    ("SQLite",                 re.compile(r"sqlite3\.\w+Error|\bSQLITE_ERROR\b", _I)),
]

# (type, severity, description, regex)
OTHER_RULES = [
    ("php_include_warning", "High",
     "PHP include()/require() failure - reveals a file path and can point to a file-inclusion flaw",
     re.compile(r"(?:Warning|Fatal error|Notice):\s*(?:include|require)(?:_once)?\([^)\n]*\)[^\n]{0,120}", _I)),

    ("sensitive_file", "High",
     "System password file contents exposed (/etc/passwd style line)",
     re.compile(r"\broot:[x*]:0:0:[^\n]{0,60}", _I)),

    ("php_error", "Medium",
     "PHP error message - reveals script name and line number",
     re.compile(r"(?:Fatal error|Warning|Notice|Parse error|Deprecated):(?!\s*(?:include|require))"
                r"[^\n]{0,200}?\bon line \d+", _I)),

    ("file_path", "Medium",
     "Server file path disclosed (reveals directory structure)",
     re.compile(r"(?:/var/www/|/srv/|/opt/|/home/[\w.\-]+/)[^\s'\"<>()\[\],;|]+"
                r"|\b[A-Za-z]:\\(?:[\w.\-]+\\)*[\w.\-]+", _I)),

    ("stack_trace", "Medium",
     "Stack trace exposed - reveals internal code structure",
     re.compile(r"Traceback \(most recent call last\)"
                r"|\bStack trace:"
                r"|#\d+\s+/[^\s]+\(\d+\):[^\n]{0,80}"
                r"|\bat\s+[\w$.]+\([\w$]+\.java:\d+\)"
                r"|Exception in thread \"[^\"]*\"", _I)),

    ("version_disclosure", "Low",
     "Software name and version disclosed (helps an attacker pick known exploits)",
     re.compile(r"\b(?:PHP|Apache|nginx|OpenSSL|Python|Tomcat|Microsoft-IIS|mod_ssl|Jetty|Node\.js)"
                r"/\d+(?:\.\d+)+[\w.+~\-]*", _I)),
]

# spaCy entity labels we accept, and the technology words an entity must contain
_SPACY_LABELS = ("ORG", "PRODUCT")
_TECH_WORDS = re.compile(
    r"\b(?:mysql|mariadb|oracle|postgres(?:ql)?|microsoft sql server|sql server|sqlite|mongodb|"
    r"apache|nginx|tomcat|iis|ubuntu|debian|centos|php|windows|linux)\b", _I)


def _clean(value: str) -> str:
    """Trim spaces and trailing punctuation, then shorten very long values."""
    value = value.strip().rstrip(".,;:'\"")
    if len(value) > MAX_VALUE_CHARS:
        value = value[:MAX_VALUE_CHARS] + "..."
    return value


def find_leaked_items(text: str) -> list:
    
    if not text:
        return []
    text = str(text)[:MAX_TEXT_CHARS]
    # PHP error pages wrap words in HTML:  <b>Warning</b>:  include(...) in <b>/var/www/x.php</b> on line <b>12</b>
    # Remove the tags first so the patterns below see plain text.
    text = _TAGS.sub("", text)

    items = []
    seen = set()
    per_type = {}

    def add(item_type, severity, value, description, source="regex"):
        value = _clean(value)
        if not value:
            return
        key = (item_type, value.lower())
        if key in seen or per_type.get(item_type, 0) >= MAX_PER_TYPE:
            return
        seen.add(key)
        per_type[item_type] = per_type.get(item_type, 0) + 1
        items.append({
            "type": item_type,
            "severity": severity,
            "value": value,
            "description": description,
            "source": source,
        })

    # 1. Database error messages (MySQL error, ORA-, SQLSTATE ...)
    for technology, rx in DB_ERROR_RULES:
        for m in rx.finditer(text):
            add("database_error", "High", m.group(0),
                f"{technology} database error exposed (reveals the database engine and query structure)")

    # 2. PHP include warnings, file paths, stack traces, versions ...
    for item_type, severity, description, rx in OTHER_RULES:
        for m in rx.finditer(text):
            add(item_type, severity, m.group(0), description)

    # 3. spaCy NER: product / vendor names that regex did not already report
    if nlp is not None:
        known = " ".join(i["value"].lower() for i in items)
        for ent in nlp(text[:5000]).ents:
            if ent.label_ in _SPACY_LABELS and _TECH_WORDS.search(ent.text):
                if ent.text.lower() not in known:
                    add("technology_disclosure", "Low", ent.text,
                        "Product or vendor name found by spaCy NER (reveals the technology stack)",
                        source="spacy")

    items.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 9), i["type"]))
    return items



if __name__ == "__main__":

    SAMPLES = [
        ("MySQL error with path, stack trace and versions",
         "Fatal error: mysql_fetch_array() expects parameter 1 to be resource, boolean given "
         "in /var/www/html/login.php on line 42\n"
         "Stack trace:\n"
         "  #0 /var/www/html/login.php(42): mysql_fetch_array()\n"
         "Server: Apache/2.4.41 (Ubuntu) PHP/7.4.3"),
        ("PHP include warning (DVWA style)",
         "Warning: include(config.inc.php): failed to open stream: No such file or directory "
         "in /var/www/html/dvwa/index.php on line 12"),
        ("PHP warning in HTML form (what DVWA really prints)",
         "<br />\n<b>Warning</b>:  include(): Failed opening 'x.php' for inclusion in "
         "<b>/var/www/html/dvwa/vulnerabilities/fi/index.php</b> on line <b>36</b><br />"),
        ("Oracle + SQLSTATE",
         "ORA-00933: SQL command not properly ended. Oracle Database 11g Enterprise Edition. "
         "SQLSTATE[42000]: Syntax error or access violation"),
        ("Normal safe response",
         "Invalid credentials. Please try again."),
    ]

    print("=" * 64)
    print("TESTING find_leaked_items()")
    print("=" * 64)
    for name, body in SAMPLES:
        result = find_leaked_items(body)
        print(f"\n  {name}  ->  {len(result)} item(s)")
        for it in result:
            print(f"    [{it['severity']:6s}] {it['type']:22s} {it['value'][:60]}   ({it['source']})")