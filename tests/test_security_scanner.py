'''
Tests for security scanner

Why test this?
- Scanner is critical infrastructure
- Must handle edge cases (empty repos, no vulnerabilities, etc.)
- Validates our data parsing is correct
'''

import pytest
from pathlib import Path
from src.tools.security_scanner import SecurityScanner, Vulnerability


def test_scanner_initialization():
    '''Test scanner can be created'''
    scanner = SecurityScanner()
    assert scanner.min_severity == 'LOW'
    
    scanner_high = SecurityScanner(min_severity='HIGH')
    assert scanner_high.min_severity == 'HIGH'


def test_scan_vulnerable_repository():
    '''Test scanning our vulnerable Flask app'''
    scanner = SecurityScanner(min_severity='MEDIUM')
    
    # Path to vulnerable app (adjust if your path is different)
    #vulnerable_repo = Path.cwd().parent / 'vulnerable-flask-app'
    vulnerable_repo = Path(r"C:\Users\rsale\Documents\vulnerable-flask-app")

    
    if not vulnerable_repo.exists():
        pytest.skip(f"Vulnerable repo not found at {vulnerable_repo}")
    
    # Scan the repository
    vulnerabilities = scanner.scan_repository(str(vulnerable_repo))
    
    # Assertions
    assert len(vulnerabilities) > 0, "Should find vulnerabilities in vulnerable app"
    assert all(isinstance(v, Vulnerability) for v in vulnerabilities)
    
    # Check we found the SQL injection
    sql_injection = [v for v in vulnerabilities if 'SQL' in v.issue_text.upper()]
    assert len(sql_injection) > 0, "Should detect SQL injection vulnerability"

    print(f"\n✅ Found {len(vulnerabilities)} vulnerabilities")
    for v in vulnerabilities[:3]:  # Print first 3
        print(f"   - {v}")
    summary = scanner.get_summary(vulnerabilities)
    print("\n--- Scan Summary ---")
    for k, v in summary.items():
        print(f"{k.capitalize():<10}: {v}")



def test_vulnerability_properties():
    '''Test Vulnerability object properties'''
    vuln = Vulnerability(
        severity='HIGH',
        confidence='HIGH',
        issue_text='SQL injection possible',
        filename='app.py',
        line_number=42,
        code='query = f\"SELECT * FROM users WHERE id={user_id}\"',
        cwe_id='CWE-89',
        test_id='B608'
    )
    
    assert vuln.is_critical == True
    assert vuln.is_high_priority == True
    assert 'SQL injection' in str(vuln)


def test_scanner_summary():
    '''Test summary statistics generation'''
    scanner = SecurityScanner()
    
    vulnerabilities = [
        Vulnerability('HIGH', 'HIGH', 'Test 1', 'a.py', 1, 'code', 'CWE-1', 'T1'),
        Vulnerability('HIGH', 'MEDIUM', 'Test 2', 'b.py', 2, 'code', 'CWE-2', 'T2'),
        Vulnerability('MEDIUM', 'HIGH', 'Test 3', 'c.py', 3, 'code', 'CWE-3', 'T3'),
        Vulnerability('LOW', 'LOW', 'Test 4', 'd.py', 4, 'code', 'CWE-4', 'T4'),
    ]
    
    summary = scanner.get_summary(vulnerabilities)
    
    assert summary['total'] == 4
    assert summary['critical'] == 1  # Only HIGH/HIGH
    assert summary['high'] == 2
    assert summary['medium'] == 1
    assert summary['low'] == 1


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, '-v'])
