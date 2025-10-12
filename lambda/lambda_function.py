"""
AWS Lambda Handler for CodeGuardian

This Lambda function:
1. Receives analysis requests from API Gateway
2. Runs CodeGuardian autonomous agent
3. Returns results in real-time
"""

import json
import os
import sys
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main Lambda handler
    
    Event structure:
    {
        "repository": "demo" or custom path,
        "mode": "quick" or "deep"
    }
    """
    
    logger.info('CodeGuardian Lambda invoked')
    logger.info(f'Event: {json.dumps(event)}')
    
    # Parse request
    try:
        # Handle both direct invocation and API Gateway
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        repository = body.get('repository', 'demo')
        mode = body.get('mode', 'quick')
        
        logger.info(f'Repository: {repository}, Mode: {mode}')
        
        # For demo, return simulated results
        # In production, this will run actual CodeGuardian agent
        if repository == 'demo':
            result = run_demo_analysis()
        else:
            result = {
                'success': False,
                'error': 'Custom repositories coming soon'
            }
        
        # Return response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',  # Enable CORS
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            'body': json.dumps(result)
        }
        
    except Exception as e:
        logger.error(f'Error: {str(e)}', exc_info=True)
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'success': False,
                'error': str(e)
            })
        }

def run_demo_analysis():
    """
    Run demo analysis (simulated for now)
    
    In production, this would:
    1. Import CodeGuardian agent
    2. Run autonomous analysis
    3. Return real results
    """
    
    # Simulated results matching what frontend expects
    return {
        'success': True,
        'timestamp': datetime.utcnow().isoformat(),
        'stats': {
            'total_vulnerabilities': 23,
            'tools_called': 7,
            'files_read': 3,
            'fixes_generated': 3
        },
        'progress': [
            {
                'step': 1,
                'icon': '🔍',
                'text': 'Agent decided: "I need to scan for vulnerabilities"',
                'subtext': 'Calling scan_repository tool...',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'step': 2,
                'icon': '✅',
                'text': 'scan_repository completed',
                'subtext': 'Found 23 HIGH severity vulnerabilities',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'step': 3,
                'icon': '🧠',
                'text': 'Agent reasoning: "I need context to generate accurate fixes"',
                'subtext': 'Calling read_file_content tool...',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'step': 4,
                'icon': '✅',
                'text': 'read_file_content completed (3 files)',
                'subtext': 'Retrieved full context including imports',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'step': 5,
                'icon': '🔧',
                'text': 'Agent decided: "I should validate my fix proposals"',
                'subtext': 'Calling validate_python_syntax tool...',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'step': 6,
                'icon': '✅',
                'text': 'validate_python_syntax completed (3 fixes)',
                'subtext': 'All proposed fixes are syntactically valid',
                'timestamp': datetime.utcnow().isoformat()
            }
        ],
        'vulnerabilities': [
            {
                'title': 'SQL Injection in Login Function',
                'severity': 'high',
                'file': 'app.py',
                'line': 42,
                'description': 'User input directly concatenated into SQL query',
                'before': "query = f\"SELECT * FROM users WHERE username='{username}'\"",
                'after': 'query = "SELECT * FROM users WHERE username=?"\ncursor.execute(query, (username,))',
                'reasoning': 'Agent analyzed sqlite3 usage and recommended parameterized queries'
            },
            {
                'title': 'Hardcoded Secret Key',
                'severity': 'high',
                'file': 'app.py',
                'line': 8,
                'description': 'Flask secret key hardcoded in source code',
                'before': "app.secret_key = 'super_secret_key_12345'",
                'after': "import os\napp.secret_key = os.getenv('SECRET_KEY')",
                'reasoning': 'Agent recommended environment variable usage'
            },
            {
                'title': 'Debug Mode in Production',
                'severity': 'medium',
                'file': 'app.py',
                'line': 76,
                'description': 'Flask app running with debug=True',
                'before': "app.run(debug=True, host='0.0.0.0')",
                'after': "debug = os.getenv('FLASK_DEBUG', 'False') == 'True'\napp.run(debug=debug)",
                'reasoning': 'Agent recommended environment-based configuration'
            }
        ]
    }
