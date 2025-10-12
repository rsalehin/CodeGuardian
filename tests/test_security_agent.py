"""
Test the Security Remediation Agent
"""

import sys
from pathlib import Path

# Add src to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.agents.security_agent import SecurityRemediationAgent
from src.tools.security_scanner import SecurityScanner, Vulnerability


def test_agent_initialization():
    """Test agent can be created"""
    agent = SecurityRemediationAgent(repo_path='.')
    assert agent.repo_path == '.'
    assert agent.bedrock is not None
    print('✅ Agent initialized')


def test_agent_analyze_vulnerability():
    """
    Test agent can analyze a vulnerability
    
    This is the CORE test - validates the entire agent flow
    """
    agent = SecurityRemediationAgent(repo_path='.')
    
    # Create a test vulnerability (SQL injection)
    vuln = Vulnerability(
        severity='HIGH',
        confidence='HIGH',
        issue_text='Possible SQL injection vector through string-based query construction',
        filename='app.py',
        line_number=42,
        code='query = f\"SELECT * FROM users WHERE username=\'{username}\'\"',
        cwe_id='CWE-89',
        test_id='B608'
    )
    
    print(f'\n🔍 Testing agent analysis...')
    
    # Have agent analyze it
    analysis = agent.analyze_vulnerability(vuln)
    
    # Verify structure
    assert 'vulnerability_id' in analysis
    assert 'analysis' in analysis
    assert len(analysis['analysis']) > 50  # Should be detailed
    
    # Verify reasoning was logged
    reasoning = agent.get_reasoning_chain()
    assert len(reasoning) > 0
    assert reasoning[0]['step'] == 'analyze_vulnerability'
    
    print(f'\n✅ Agent analysis complete')
    print(f'Analysis length: {len(analysis["analysis"])} characters')
    print(f'\nFirst 300 chars of analysis:')
    print(analysis['analysis'][:300] + '...')
    print(f'\n📊 Reasoning chain: {len(reasoning)} steps logged')


def test_agent_with_real_vulnerabilities():
    """
    Test agent with real vulnerabilities from scanner
    """
    # FIXED: Path to vulnerable app inside codeGuardian folder
    # WHY? Your vulnerable-flask-app is inside codeGuardian, not next to it
    vulnerable_repo = Path(__file__).parent.parent / 'vulnerable-flask-app'
    
    print(f'\n🔍 Looking for vulnerable repo at: {vulnerable_repo}')
    
    if not vulnerable_repo.exists():
        pytest.skip(f'Vulnerable repo not found at {vulnerable_repo}')
    
    # Scan for vulnerabilities
    scanner = SecurityScanner(min_severity='HIGH')
    vulnerabilities = scanner.scan_repository(str(vulnerable_repo))
    
    if len(vulnerabilities) == 0:
        pytest.skip('No HIGH severity vulnerabilities found')
    
    print(f'\n📊 Found {len(vulnerabilities)} HIGH severity vulnerabilities')
    
    # Initialize agent
    agent = SecurityRemediationAgent(repo_path=str(vulnerable_repo))
    
    # Analyze first vulnerability
    first_vuln = vulnerabilities[0]
    print(f'🔍 Analyzing: {first_vuln.issue_text}')
    
    analysis = agent.analyze_vulnerability(first_vuln)
    
    # Verify
    assert 'analysis' in analysis
    assert len(agent.get_reasoning_chain()) > 0
    
    print(f'\n✅ Real vulnerability analyzed')
    print(f'Vulnerability: {first_vuln.issue_text}')
    print(f'Agent provided {len(analysis["analysis"])} character analysis')
    print(f'\n📝 Analysis preview:')
    print(analysis['analysis'][:400] + '...')


if __name__ == '__main__':
    # Run tests when executed directly
    pytest.main([__file__, '-v', '-s'])
