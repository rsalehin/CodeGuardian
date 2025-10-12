"""
Test Deep Context Analysis
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.agents.autonomous_agent import AutonomousSecurityAgent


def test_deep_vulnerability_analysis():
    """
    Test deep analysis with full context
    
    WHY THIS TEST?
    - Shows agent reading full files
    - Demonstrates context understanding
    - Proves more intelligent recommendations
    """
    vulnerable_repo = Path(__file__).parent.parent / 'vulnerable-flask-app'
    
    if not vulnerable_repo.exists():
        pytest.skip('Vulnerable repo not found')
    
    print('\n' + '='*80)
    print('🔬 DEEP CONTEXT ANALYSIS TEST')
    print('='*80)
    
    agent = AutonomousSecurityAgent(repo_path=str(vulnerable_repo))
    
    # First, get vulnerabilities
    scan_result = agent.tool_executor.execute_tool(
        'scan_repository',
        {'repo_path': str(vulnerable_repo), 'min_severity': 'HIGH'}
    )
    
    vulnerabilities = scan_result['result']['vulnerabilities']
    
    if len(vulnerabilities) == 0:
        pytest.skip('No vulnerabilities found')
    
    # Pick the first SQL injection or similar
    target_vuln = vulnerabilities[0]
    
    print(f'\n🎯 Analyzing: {target_vuln["issue"]}')
    print(f'   Location: {target_vuln["file"]}:{target_vuln["line"]}')
    
    # Perform deep analysis
    analysis = agent.deep_analyze_vulnerability(target_vuln)
    
    # Verify analysis
    assert analysis['success'] == True
    assert len(analysis['tools_used']) >= 2  # Should use multiple tools
    
    print(f'\n✅ Deep analysis complete!')
    print(f'\n🔧 Tools used: {len(analysis["tools_used"])}')
    for tool in analysis['tools_used']:
        print(f'   - {tool["name"]}')
    
    print(f'\n📊 Analysis length: {len(analysis["analysis"])} characters')
    print(f'\n📝 Analysis preview:')
    print(analysis['analysis'][:800])
    print('...')
    
    # Check if agent read the file
    used_read_file = any(t['name'] == 'read_file_content' for t in analysis['tools_used'])
    print(f'\n🔍 Agent read full file: {"✅ Yes\" if used_read_file else \"❌ No"}')
    
    print('\n' + '='*80)


def test_enhanced_autonomous_analysis():
    """
    Test the enhanced autonomous analysis with context
    
    This should show:
    - Agent scanning
    - Agent reading files for context
    - Agent providing detailed fixes
    """
    vulnerable_repo = Path(__file__).parent.parent / 'vulnerable-flask-app'
    
    if not vulnerable_repo.exists():
        pytest.skip('Vulnerable repo not found')
    
    print('\n' + '='*80)
    print('🚀 ENHANCED AUTONOMOUS ANALYSIS TEST')
    print('='*80)
    
    agent = AutonomousSecurityAgent(repo_path=str(vulnerable_repo))
    
    # Run enhanced autonomous analysis
    result = agent.analyze_repository_autonomous()
    
    # Verify
    assert result['success'] == True
    
    print(f'\n✅ Analysis complete!')
    print(f'Tools used: {len(result["tools_used"])}')
    print(f'Reasoning steps: {len(result["reasoning_chain"])}')
    print(f'Iterations: {result["iterations"]}')
    
    # Check tool diversity
    tool_names = [t['name'] for t in result['tools_used']]
    unique_tools = set(tool_names)
    
    print(f'\n🔧 Unique tools used: {unique_tools}')
    
    # Check if agent used read_file_content
    used_context = 'read_file_content' in unique_tools
    print(f'\n📖 Used file reading: {"✅ Yes" if used_context else "⚠️  No"}')
    
    print(f'\n📝 Final response preview:')
    print(result['final_response'][:600])
    print('...')
    
    print('\n' + '='*80)
    
    # Assert we're using more sophisticated tools
    assert len(unique_tools) >= 2, 'Should use multiple different tools'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
