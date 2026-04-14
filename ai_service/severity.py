"""
VULKN — ai_service/severity.py
Severity scoring rules module.

Day 24:
  create ai_service/severity.py
  Rules:
    If SQLi + confident > 0.9 = Critical
    If XSS + confident > 0.8 = High
    If error leak detected = Medium
  POST /score endpoint (already in main.py — imports from here)

This module contains the scoring logic as a reusable function.
Other parts of VULKN can import it without going through the HTTP endpoint.
Usage: from ai_service.severity import score_finding
"""

# ── CVSS base scores per vulnerability type ───────────────────────────
# These are industry-standard CVSS 3.1 base scores
CVSS_BASE = {
    "SQLi":          9.8,   # SQL Injection — Critical by default
    "XSS_stored":    8.8,   # Stored XSS — script runs for all users
    "XSS_reflected": 6.1,   # Reflected XSS — needs victim to click link
    "XSS":           7.0,   # Generic XSS (when type not specified)
    "OpenPort":      5.3,   # Open port — information disclosure
    "PathTraversal": 7.5,   # Path/directory traversal
    "DirTraversal":  7.5,   # Same as PathTraversal
    "CSRF":          6.5,   # Cross-Site Request Forgery
}


def cvss_to_label(score: float) -> str:
    """Converts a numeric CVSS score to a severity label string."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def score_finding(
    vuln_type:            str,
    confidence:           float,
    confirmed_vulnerable: bool,
    error_keywords_found: bool = False
) -> dict:
    """
    Applies the Day 24 severity rules and returns a severity rating.

    Args:
        vuln_type:            Type of vulnerability (SQLi, XSS, CSRF etc)
        confidence:           AI confidence from /classify-response (0.0 to 1.0)
        confirmed_vulnerable: True if the scanner confirmed the vulnerability
        error_keywords_found: True if SQL/server error strings were in response

    Returns:
        {
            "severity":   "Critical" | "High" | "Medium" | "Low",
            "cvss_score": float,
            "reasoning":  list of strings explaining the decision
        }

    Rules (from document):
        Rule 1: If SQLi + confident > 0.9 = Critical
        Rule 2: If XSS + confident > 0.8 = High
        Rule 3: If error leak detected = Medium
        Rule 4: confirmed + standard CVSS score
        Rule 5: not confirmed = Low
    """
    base_score = CVSS_BASE.get(vuln_type, 5.0)
    reasoning  = []

    # ── Rule 1: SQLi + confident > 0.9 = Critical ─────────────────────
    if vuln_type == "SQLi" and confidence > 0.9 and confirmed_vulnerable:
        final_score = 9.8
        severity    = "Critical"
        reasoning.append(
            f"Rule 1: SQLi confirmed, confidence {confidence:.2f} > 0.9 "
            f"→ Critical (CVSS 9.8)"
        )

    # ── Rule 2: XSS + confident > 0.8 = High ──────────────────────────
    elif vuln_type in ("XSS", "XSS_stored", "XSS_reflected") and \
            confidence > 0.8 and confirmed_vulnerable:
        final_score = 8.0
        severity    = "High"
        reasoning.append(
            f"Rule 2: XSS confirmed, confidence {confidence:.2f} > 0.8 "
            f"→ High (CVSS 8.0)"
        )

    # ── Rule 3: error leak detected = Medium ──────────────────────────
    elif error_keywords_found:
        final_score = 5.5
        severity    = "Medium"
        reasoning.append(
            "Rule 3: Error keywords in response = information disclosure "
            "→ Medium (CVSS 5.5)"
        )

    # ── Rule 4: confirmed, use standard CVSS base score ───────────────
    elif confirmed_vulnerable:
        final_score = base_score
        severity    = cvss_to_label(final_score)
        reasoning.append(
            f"Rule 4: Confirmed vulnerable, base CVSS={base_score} "
            f"→ {severity}"
        )

    # ── Rule 5: not confirmed, reduce score ───────────────────────────
    else:
        final_score = base_score * 0.5
        severity    = "Low"
        reasoning.append(
            f"Rule 5: Not confirmed, reduced score "
            f"{base_score} × 0.5 = {final_score:.1f} → Low"
        )

    return {
        "severity":   severity,
        "cvss_score": round(final_score, 1),
        "reasoning":  reasoning
    }


# ── Run this file directly to test all rules ──────────────────────────
if __name__ == "__main__":

    TEST_CASES = [
        {
            "name":                 "SQLi confirmed high confidence",
            "vuln_type":            "SQLi",
            "confidence":           0.95,
            "confirmed_vulnerable": True,
            "error_keywords_found": False,
            "expected":             "Critical"
        },
        {
            "name":                 "SQLi confirmed but confidence exactly 0.9 (boundary)",
            "vuln_type":            "SQLi",
            "confidence":           0.90,
            "confirmed_vulnerable": True,
            "error_keywords_found": False,
            "expected":             "Critical"  # Rule 4 fires (not > 0.9) → CVSS 9.8 = Critical
        },
        {
            "name":                 "SQLi confirmed low confidence",
            "vuln_type":            "SQLi",
            "confidence":           0.75,
            "confirmed_vulnerable": True,
            "error_keywords_found": False,
            "expected":             "Critical"  # Rule 4: CVSS 9.8 = Critical
        },
        {
            "name":                 "XSS confirmed high confidence",
            "vuln_type":            "XSS",
            "confidence":           0.92,
            "confirmed_vulnerable": True,
            "error_keywords_found": False,
            "expected":             "High"
        },
        {
            "name":                 "XSS confirmed low confidence",
            "vuln_type":            "XSS",
            "confidence":           0.65,
            "confirmed_vulnerable": True,
            "error_keywords_found": False,
            "expected":             "High"  # Rule 4: CVSS 7.0 = High
        },
        {
            "name":                 "SQL error in response (not confirmed)",
            "vuln_type":            "SQLi",
            "confidence":           0.40,
            "confirmed_vulnerable": False,
            "error_keywords_found": True,
            "expected":             "Medium"
        },
        {
            "name":                 "PathTraversal confirmed",
            "vuln_type":            "PathTraversal",
            "confidence":           0.80,
            "confirmed_vulnerable": True,
            "error_keywords_found": False,
            "expected":             "High"  # Rule 4: CVSS 7.5 = High
        },
        {
            "name":                 "CSRF not confirmed",
            "vuln_type":            "CSRF",
            "confidence":           0.30,
            "confirmed_vulnerable": False,
            "error_keywords_found": False,
            "expected":             "Low"
        },
    ]

    print("=" * 60)
    print("TESTING SEVERITY RULES — ai_service/severity.py")
    print("=" * 60)

    all_pass = True
    for tc in TEST_CASES:
        result = score_finding(
            vuln_type=tc["vuln_type"],
            confidence=tc["confidence"],
            confirmed_vulnerable=tc["confirmed_vulnerable"],
            error_keywords_found=tc["error_keywords_found"]
        )
        ok = "PASS" if result["severity"] == tc["expected"] else "FAIL"
        if ok == "FAIL":
            all_pass = False
        print(f"\n  [{ok}] {tc['name']}")
        print(f"        type={tc['vuln_type']}  conf={tc['confidence']}  "
              f"confirmed={tc['confirmed_vulnerable']}  err_kw={tc['error_keywords_found']}")
        print(f"        Result   : {result['severity']}  CVSS={result['cvss_score']}")
        print(f"        Reasoning: {result['reasoning'][0]}")

    print()
    print("=" * 60)
    if all_pass:
        print("ALL TESTS PASSED — severity.py is correct")
    else:
        print("SOME TESTS FAILED — check above")
    print("=" * 60)