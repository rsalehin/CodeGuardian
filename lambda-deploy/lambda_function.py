"""
CodeGuardian Lambda Handler - FIXED IMPORTS

Key learning: Import paths differ between development and Lambda!
We need to handle BOTH environments.
"""

import json
import os
import sys
import logging
import traceback
from datetime import datetime
from pathlib import Path

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# SMART PATH HANDLING - Works in both local and Lambda!
def setup_paths():
    """
    Setup import paths for both local testing and Lambda deployment
    
    Lambda unpacks to: /var/task/
    Local testing runs from: ./lambda-deploy/
    
    This function handles BOTH cases!
    """
    possible_paths = [
        '/var/task/src',              # Lambda environment
        '/var/task',                  # Lambda root
        './package/src',              # Local testing (packaged)
        './src',                      # Local testing (direct)
        str(Path(__file__).parent / 'package' / 'src'),  # Relative to script
        str(Path(__file__).parent / 'src'),              # Relative to script
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and path not in sys.path:
            sys.path.insert(0, path)
            logger.info(f'✅ Added to path: {path}')

# Setup paths BEFORE importing our modules
setup_paths()

def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    
    logger.info('=' * 80)
    logger.info('🤖 CodeGuardian Lambda - REAL AGENT EXECUTION')
    logger.info('=' * 80)
    
    try:
        # Parse request
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        repository_choice = body.get('repository', 'flask')
        
        logger.info(f'📁 Selected repository: {repository_choice}')
        
        # Map repository choices to paths
        # Check both Lambda and local paths
        base_paths = [
            '/var/task/repos',
            './package/repos',
            './repos',
            str(Path(__file__).parent / 'package' / 'repos'),
            str(Path(__file__).parent / 'repos'),
        ]
        
        repo_names = {
            'flask': 'vulnerable-flask-app',
            'django': 'vulnerable-django-api',
            'express': 'vulnerable-express-api'
        }
        
        repo_name = repo_names.get(repository_choice, 'vulnerable-flask-app')
        repo_path = None
        
        # Find the repository
        for base in base_paths:
            test_path = os.path.join(base, repo_name)
            if os.path.exists(test_path):
                repo_path = test_path
                logger.info(f'✅ Found repository at: {repo_path}')
                break
        
        if not repo_path:
            raise ValueError(f'Repository not found: {repository_choice}. Checked: {base_paths}')
        
        # Run REAL CodeGuardian analysis
        result = run_real_codeguardian_analysis(repo_path, repository_choice)
        
        logger.info('✅ Analysis complete!')
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            'body': json.dumps(result)
        }
        
    except Exception as e:
        logger.error('=' * 80)
        logger.error('❌ LAMBDA ERROR')
        logger.error('=' * 80)
        logger.error(f'Error: {str(e)}')
        logger.error(f'Traceback: {traceback.format_exc()}')
        
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            })
        }

def run_real_codeguardian_analysis(repo_path, repo_name):
    """
    Run the ACTUAL CodeGuardian autonomous agent
    """
    
    logger.info('🚀 Initializing REAL CodeGuardian Agent...')
    
    try:
        # NOW import - paths are already setup!
        logger.info('📦 Importing CodeGuardian modules...')
        
        from agents.autonomous_agent import AutonomousSecurityAgent
        from tools.security_scanner import SecurityScanner
        
        logger.info('✅ Modules imported successfully!')
        
        # Initialize scanner
        logger.info('🔍 Initializing security scanner...')
        scanner = SecurityScanner(min_severity='HIGH')
        
        # Scan repository
        logger.info(f'🔬 Scanning repository: {repo_path}')
        vulnerabilities = scanner.scan_repository(repo_path)
        
        logger.info(f'📊 Found {len(vulnerabilities)} HIGH severity vulnerabilities')
        
        if len(vulnerabilities) == 0:
            return {
                'success': True,
                'repository': repo_name,
                'message': 'No HIGH severity vulnerabilities found',
                'stats': {
                    'total_vulnerabilities': 0,
                    'tools_called': 1,
                    'files_read': 0,
                    'fixes_generated': 0
                },
                'vulnerabilities': []
            }
        
        # Initialize autonomous agent
        logger.info('🤖 Initializing autonomous agent...')
        agent = AutonomousSecurityAgent(repo_path=repo_path)
        
        logger.info('🧠 Running autonomous analysis...')
        
        # Run REAL autonomous analysis
        analysis_result = agent.analyze_repository_autonomous()
        
        logger.info('✅ Autonomous analysis complete!')
        logger.info(f'Success: {analysis_result.get("success")}')
        logger.info(f'Tools used: {len(analysis_result.get("tools_used", []))}')
        
        # Get reasoning chain
        reasoning_chain = agent.get_reasoning_chain()
        
        logger.info(f'📊 Reasoning chain length: {len(reasoning_chain)}')
        
        # Format results
        return format_results_for_frontend(
            repo_name=repo_name,
            vulnerabilities=vulnerabilities,
            analysis_result=analysis_result,
            reasoning_chain=reasoning_chain
        )
        
    except Exception as e:
        logger.error(f'❌ Analysis error: {str(e)}')
        logger.error(traceback.format_exc())
        raise

def format_results_for_frontend(repo_name, vulnerabilities, analysis_result, reasoning_chain):
    """Format results for frontend"""
    
    # Convert reasoning chain
    progress_items = []
    for idx, step in enumerate(reasoning_chain):
        tools_requested = step.get('tools_requested', [])
        
        if tools_requested:
            for tool in tools_requested:
                progress_items.append({
                    'step': len(progress_items) + 1,
                    'icon': get_tool_icon(tool),
                    'text': f'Agent decided to use: {tool}',
                    'subtext': f'Step {idx + 1} of autonomous analysis',
                    'timestamp': step.get('timestamp', '')
                })
    
    # Convert vulnerabilities
    vuln_list = []
    for vuln in vulnerabilities[:5]:
        vuln_dict = {
            'title': vuln.issue_text[:80],
            'severity': vuln.severity.lower(),
            'file': vuln.filename,
            'line': vuln.line_number,
            'description': vuln.issue_text,
            'cwe_id': vuln.cwe_id,
            'before': vuln.code,
            'after': generate_fix_hint(vuln),
            'reasoning': f'Real agent analysis: {vuln.issue_text}',
            'is_real': True
        }
        vuln_list.append(vuln_dict)
    
    return {
        'success': True,
        'repository': repo_name,
        'timestamp': datetime.utcnow().isoformat(),
        'agent_type': 'REAL_AUTONOMOUS',
        'model': 'Amazon Bedrock Nova Lite',
        'stats': {
            'total_vulnerabilities': len(vulnerabilities),
            'tools_called': len(analysis_result.get('tools_used', [])),
            'files_read': count_file_reads(analysis_result.get('tools_used', [])),
            'fixes_generated': min(len(vulnerabilities), 5)
        },
        'progress': progress_items,
        'reasoning_chain': reasoning_chain,
        'final_response': analysis_result.get('final_response', ''),
        'vulnerabilities': vuln_list,
        'tools_used': analysis_result.get('tools_used', [])
    }

def get_tool_icon(tool_name):
    """Get emoji for tool"""
    icons = {
        'scan_repository': '🔍',
        
        'read_file_content': '📄',
        'analyze_code_context': '🔬',
        'validate_python_syntax': '✅'
    }
    return icons.get(tool_name, '🔧')

def count_file_reads(tools_used):
    """Count file reads"""
    return sum(1 for tool in tools_used if tool.get('name') == 'read_file_content')

def generate_fix_hint(vulnerability):
    """Generate fix hint"""
    fixes = {
        'CWE-89': 'Use parameterized queries:\nquery = "SELECT * FROM users WHERE id=?"\ncursor.execute(query, (user_id,))',
        'CWE-79': 'Escape output:\nfrom markupsafe import escape\noutput = escape(user_input)',
        'CWE-798': 'Use environment variables:\nimport os\nsecret = os.getenv("SECRET_KEY")',
        'CWE-78': 'Avoid shell:\nimport subprocess\nsubprocess.run(["cmd", arg], shell=False)',
        'CWE-502': 'Use JSON:\nimport json\ndata = json.loads(user_input)'
    }
    return fixes.get(vulnerability.cwe_id, 'See OWASP guidelines for ' + str(vulnerability.cwe_id))