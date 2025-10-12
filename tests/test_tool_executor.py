"""
Test Tool Executor
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.tools.tool_executor import ToolExecutor


def test_tool_executor_initialization():
    """Test executor can be created"""
    executor = ToolExecutor(repo_path='.')
    assert executor.repo_path is not None
    print('✅ ToolExecutor initialized')


def test_scan_repository_tool():
    """Test scan_repository tool execution"""
    vulnerable_repo = Path(__file__).parent.parent / 'vulnerable-flask-app'
    
    if not vulnerable_repo.exists():
        pytest.skip('Vulnerable repo not found')
    
    executor = ToolExecutor(repo_path=str(vulnerable_repo))
    
    result = executor.execute_tool(
        tool_name='scan_repository',
        tool_input={'repo_path': str(vulnerable_repo), 'min_severity': 'HIGH'}
    )
    
    assert result['success'] == True
    assert 'result' in result
    assert result['result']['total_vulnerabilities'] > 0
    
    print(f'\n✅ Scan found {result["result"]["total_vulnerabilities"]} vulnerabilities')


def test_read_file_tool():
    """Test read_file_content tool"""
    vulnerable_repo = Path(__file__).parent.parent / 'vulnerable-flask-app'
    
    if not vulnerable_repo.exists():
        pytest.skip('Vulnerable repo not found')
    
    executor = ToolExecutor(repo_path=str(vulnerable_repo))
    
    result = executor.execute_tool(
        tool_name='read_file_content',
        tool_input={'filepath': 'app.py', 'start_line': 1, 'end_line': 20}
    )
    
    assert result['success'] == True
    assert 'result' in result
    assert len(result['result']['content']) > 0
    
    print(f'\n✅ Read file: {result["result"]["filepath"]}')
    print(f'Lines: {result["result"]["start_line"]}-{result["result"]["end_line"]}')


def test_validate_syntax_tool():
    """Test syntax validation tool"""
    executor = ToolExecutor(repo_path='.')
    
    # Test valid code
    result = executor.execute_tool(
        tool_name='validate_python_syntax',
        tool_input={'code': 'def hello():\n    print(\"Hello\")'}
    )
    
    assert result['success'] == True
    assert result['result']['valid'] == True
    
    # Test invalid code
    result = executor.execute_tool(
        tool_name='validate_python_syntax',
        tool_input={'code': 'def hello(\n    print(\"Hello\")'}  # Missing closing paren
    )
    
    assert result['success'] == True
    assert result['result']['valid'] == False
    
    print('✅ Syntax validation working')


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
