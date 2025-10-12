"""
Test Autonomous Agent with Tool Calling
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.agents.autonomous_agent import AutonomousSecurityAgent


def test_autonomous_agent_initialization():
    """Test autonomous agent can be created"""
    agent = AutonomousSecurityAgent(repo_path='.')
    assert agent.tools is not None
    assert len(agent.tools) >= 4
    print(f'\n✅ Agent initialized with {len(agent.tools)} tools')


def test_autonomous_repository_analysis():
    """
    Test full autonomous analysis - THIS IS THE BIG ONE!
    
    WHY THIS TEST MATTERS:
    - Demonstrates true autonomous behavior
    - Agent makes its own decisions
    - Uses multiple tools
    - Shows the complete workflow
    """
    vulnerable_repo = Path(__file__).parent.parent / 'vulnerable-flask-app'
    
    if not vulnerable_repo.exists():
        pytest.skip('Vulnerable repo not found')
    
    print('\n' + '='*80)
    print('🤖 AUTONOMOUS AGENT TEST - WATCH IT WORK!')
    print('='*80)
    
    agent = AutonomousSecurityAgent(repo_path=str(vulnerable_repo))
    
    # Let the agent work autonomously!
    result = agent.analyze_repository_autonomous()
    
    # Verify results
    assert result['success'] == True, 'Agent should complete successfully'
    assert len(result['tools_used']) > 0, 'Agent should use at least one tool'
    assert len(result['reasoning_chain']) > 0, 'Agent should log reasoning'
    
    print('\n' + '='*80)
    print('📊 AUTONOMOUS ANALYSIS RESULTS')
    print('='*80)
    print(f'Success: {result["success"]}')
    print(f'Tools used: {len(result["tools_used"])}')
    print(f'Reasoning steps: {len(result["reasoning_chain"])}')
    
    print('\n🔧 Tools Called:')
    for tool in result['tools_used']:
        status = '✅' if tool['success'] else '❌'
        print(f'  {status} {tool["name"]}')
    
    print('\n💭 Agent Reasoning Chain:')
    for step in result['reasoning_chain']:
        print(f'  Step {step["iteration"]}: {step.get("stop_reason", "processing")}')
        if step.get('tools_requested'):
            print(f'    → Requested: {step["tools_requested"]}')
    
    print('\n📝 Final Response Preview:')
    response = result['final_response']
    print(response[:500] + '...' if len(response) > 500 else response)
    
    print('\n' + '='*80)
    print('🎉 AUTONOMOUS AGENT TEST COMPLETE!')
    print('='*80)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
