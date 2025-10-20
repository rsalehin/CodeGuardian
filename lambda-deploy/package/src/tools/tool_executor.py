"""
Tool Executor for AgentCore

WHY THIS EXISTS?
- Agent CALLS tools, but doesn't EXECUTE them
- This is the bridge between agent decisions and actual code execution
- Handles errors, logging, and response formatting
"""

import json
import subprocess
import ast
import os
from typing import Dict, Any
from pathlib import Path
import logging

from src.tools.security_scanner import SecurityScanner

logger = logging.getLogger(__name__)


class ToolExecutor:
    """
    Executes tools called by the agent via AgentCore
    
    WHY A CLASS?
    - Maintains state (repo_path, scanner instance)
    - Centralizes error handling
    - Easy to test and mock
    """
    
    def __init__(self, repo_path: str):
        """
        Initialize tool executor
        
        Args:
            repo_path: Path to repository being analyzed
            
        WHY store repo_path?
        - Most tools need to know where the code is
        - Provides context for relative paths
        """
        self.repo_path = Path(repo_path).resolve()
        self.scanner = SecurityScanner()
        
        logger.info(f'🔧 ToolExecutor initialized for: {self.repo_path}')
    
    def execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route tool execution to appropriate handler
        
        Args:
            tool_name: Name of tool to execute
            tool_input: Input parameters for the tool
            
        Returns:
            Tool execution result
            
        WHY THIS ROUTER PATTERN?
        - Clean mapping of tool names to implementations
        - Easy to add new tools
        - Centralized error handling
        """
        handlers = {
            'scan_repository': self._scan_repository,
            'read_file_content': self._read_file_content,
            'analyze_code_context': self._analyze_code_context,
            'validate_python_syntax': self._validate_python_syntax
        }
        
        handler = handlers.get(tool_name)
        
        if not handler:
            error_msg = f'Unknown tool: {tool_name}'
            logger.error(f'❌ {error_msg}')
            return {'success': False, 'error': error_msg}
        
        try:
            logger.info(f'🔧 Executing tool: {tool_name}')
            logger.debug(f'   Input: {json.dumps(tool_input, indent=2)}')
            
            result = handler(tool_input)
            
            logger.info(f'✅ Tool executed successfully: {tool_name}')
            return {'success': True, 'result': result}
            
        except Exception as e:
            error_msg = f'Tool execution failed: {str(e)}'
            logger.error(f'❌ {error_msg}')
            return {'success': False, 'error': error_msg}
    
    def _scan_repository(self, params: Dict) -> Dict:
        """
        Execute security scan
        
        WHY THIS IMPLEMENTATION?
        - Reuses our SecurityScanner class
        - Converts Vulnerability objects to JSON-serializable dicts
        - Provides summary statistics
        """
        repo_path = params.get('repo_path', str(self.repo_path))
        min_severity = params.get('min_severity', 'MEDIUM')
        
        # Scan using our scanner
        scanner = SecurityScanner(min_severity=min_severity)
        vulnerabilities = scanner.scan_repository(repo_path)
        
        # Convert to JSON-serializable format for agent
        vuln_list = [
            {
                'id': f'vuln-{idx+1}',
                'severity': v.severity,
                'confidence': v.confidence,
                'issue': v.issue_text,
                'file': v.filename,
                'line': v.line_number,
                'code': v.code,
                'cwe_id': v.cwe_id,
                'test_id': v.test_id
            }
            for idx, v in enumerate(vulnerabilities)
        ]
        
        # Generate summary
        summary = scanner.get_summary(vulnerabilities)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'summary': summary,
            'vulnerabilities': vuln_list[:10]  # Limit to 10 to avoid token overflow
        }
    
    def _read_file_content(self, params: Dict) -> Dict:
        """
        Read file content
        
        WHY LINE NUMBERS?
        - Agent might only need specific sections
        - Saves tokens (cheaper, faster)
        - More focused context
        """
        filepath = params['filepath']
        start_line = params.get('start_line', 1)
        end_line = params.get('end_line', None)
        
        full_path = self.repo_path / filepath
        
        if not full_path.exists():
            return {'error': f'File not found: {filepath}'}
        
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        
        # Handle line ranges
        if end_line:
            content_lines = lines[start_line-1:end_line]
        else:
            content_lines = lines[start_line-1:]
        
        content = ''.join(content_lines)
        
        return {
            'filepath': filepath,
            'content': content,
            'start_line': start_line,
            'end_line': end_line or total_lines,
            'total_lines': total_lines
        }
    
    def _analyze_code_context(self, params: Dict) -> Dict:
        """
        Analyze code context using AST
        
        WHY AST?
        - Understands Python code structure
        - Can find function boundaries
        - Identifies variable scope
        - Better than regex for code analysis
        """
        filepath = params['filepath']
        line_number = params['line_number']
        
        full_path = self.repo_path / filepath
        
        if not full_path.exists():
            return {'error': f'File not found: {filepath}'}
        
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')
        
        # Parse AST
        try:
            tree = ast.parse(content)
            
            # Find function containing the line
            function_name = None
            function_start = None
            function_end = None
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                        if node.lineno <= line_number <= node.end_lineno:
                            function_name = node.name
                            function_start = node.lineno
                            function_end = node.end_lineno
                            break
            
            # Get context (10 lines before and after)
            context_start = max(1, line_number - 10)
            context_end = min(len(lines), line_number + 10)
            context_code = '\n'.join(lines[context_start-1:context_end])
            
            return {
                'line_number': line_number,
                'function_name': function_name or 'Not in a function',
                'function_lines': f'{function_start}-{function_end}' if function_start else 'N/A',
                'context_code': context_code,
                'context_lines': f'{context_start}-{context_end}'
            }
            
        except SyntaxError as e:
            return {
                'error': f'Syntax error in file: {str(e)}',
                'line_number': line_number
            }
    
    def _validate_python_syntax(self, params: Dict) -> Dict:
        """
        Validate Python syntax
        
        WHY?
        - Agent can check if its generated fixes are valid
        - Prevents suggesting broken code
        - Fast validation before actually applying changes
        """
        code = params['code']
        
        try:
            ast.parse(code)
            return {
                'valid': True,
                'message': 'Syntax is valid'
            }
        except SyntaxError as e:
            return {
                'valid': False,
                'error': str(e),
                'line': e.lineno,
                'offset': e.offset
            }
