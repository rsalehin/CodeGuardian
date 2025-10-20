"""
AgentCore Tool Definitions

WHY THIS FILE?
- AgentCore needs structured descriptions of available tools
- Agent uses these to decide which tool to call
- Think of this as the "instruction manual" for the agent

TOOL DESIGN PRINCIPLES:
- Clear, descriptive names
- Detailed descriptions (helps agent decide when to use)
- Well-defined input schemas
- Each tool does ONE thing well
"""

from typing import List, Dict


def get_tool_definitions() -> List[Dict]:
    """
    Get tool definitions for AgentCore
    
    WHY THIS FORMAT?
    - Bedrock AgentCore expects specific JSON schema
    - 'toolSpec' is the required wrapper
    - 'inputSchema' defines parameters
    
    Returns:
        List of tool definition dictionaries
    """
    
    tools = [
        {
            'toolSpec': {
                'name': 'scan_repository',
                'description': '''Scans a code repository for security vulnerabilities using Bandit security scanner. 
                Returns a list of vulnerabilities with severity, location, and description. 
                Use this when you need to find security issues in code.''',
                'inputSchema': {
                    'json': {
                        'type': 'object',
                        'properties': {
                            'repo_path': {
                                'type': 'string',
                                'description': 'Absolute path to the repository directory to scan'
                            },
                            'min_severity': {
                                'type': 'string',
                                'enum': ['LOW', 'MEDIUM', 'HIGH'],
                                'description': 'Minimum severity level to report (default: MEDIUM)'
                            }
                        },
                        'required': ['repo_path']
                    }
                }
            }
        },
        
        {
            'toolSpec': {
                'name': 'read_file_content',
                'description': '''Reads the content of a specific file in the repository. 
                Use this when you need to see the full context of vulnerable code, 
                understand surrounding functions, or analyze imports and dependencies.''',
                'inputSchema': {
                    'json': {
                        'type': 'object',
                        'properties': {
                            'filepath': {
                                'type': 'string',
                                'description': 'Path to the file to read (relative to repository root)'
                            },
                            'start_line': {
                                'type': 'integer',
                                'description': 'Optional: Line number to start reading from (1-indexed)'
                            },
                            'end_line': {
                                'type': 'integer',
                                'description': 'Optional: Line number to stop reading at (inclusive)'
                            }
                        },
                        'required': ['filepath']
                    }
                }
            }
        },
        
        {
            'toolSpec': {
                'name': 'analyze_code_context',
                'description': '''Analyzes the code context around a specific line using AST parsing. 
                Returns function scope, variable usage, imports, and data flow information. 
                Use this to understand HOW a vulnerability can be exploited and what depends on the vulnerable code.''',
                'inputSchema': {
                    'json': {
                        'type': 'object',
                        'properties': {
                            'filepath': {
                                'type': 'string',
                                'description': 'Path to the Python file to analyze'
                            },
                            'line_number': {
                                'type': 'integer',
                                'description': 'Line number to analyze (1-indexed)'
                            }
                        },
                        'required': ['filepath', 'line_number']
                    }
                }
            }
        },
        
        {
            'toolSpec': {
                'name': 'validate_python_syntax',
                'description': '''Validates that a Python code string has correct syntax. 
                Use this to check if your proposed fix is syntactically valid before recommending it. 
                Returns True if valid, or error details if invalid.''',
                'inputSchema': {
                    'json': {
                        'type': 'object',
                        'properties': {
                            'code': {
                                'type': 'string',
                                'description': 'Python code to validate'
                            }
                        },
                        'required': ['code']
                    }
                }
            }
        }
    ]
    
    return tools


def get_tool_names() -> List[str]:
    """
    Get list of available tool names
    
    WHY?
    - Useful for logging
    - Validation
    - Testing
    """
    tools = get_tool_definitions()
    return [tool['toolSpec']['name'] for tool in tools]
