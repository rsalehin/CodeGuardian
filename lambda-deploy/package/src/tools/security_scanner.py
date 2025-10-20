"""
Security Scanner - Lambda Compatible Version

Uses Bandit Python API instead of CLI
"""

import os
import logging
from pathlib import Path
from typing import List
from dataclasses import dataclass

# Import Bandit Python API
from bandit.core import manager as bandit_manager
from bandit.core import config as bandit_config

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Vulnerability data class"""
    severity: str
    confidence: str
    issue_text: str
    filename: str
    line_number: int
    code: str
    cwe_id: str
    test_id: str

class SecurityScanner:
    """Security scanner using Bandit Python API"""
    
    def __init__(self, min_severity: str = 'MEDIUM'):
        self.min_severity = min_severity
        logger.info(f'🔍 SecurityScanner initialized (min severity: {min_severity})')
    
    def scan_repository(self, repo_path: str) -> List[Vulnerability]:
        """
        Scan repository using Bandit Python API
        
        This works in Lambda because it uses the Python library,
        not the command-line tool!
        """
        
        logger.info(f'🔬 Scanning repository: {repo_path}')
        
        try:
            # Find Python files
            python_files = self._find_python_files(repo_path)
            
            if not python_files:
                logger.warning(f'⚠️  No Python files found in {repo_path}')
                return []
            
            logger.info(f'📁 Found {len(python_files)} Python files')
            
            # Configure Bandit
            b_conf = bandit_config.BanditConfig()
            
            # Create Bandit manager
            b_mgr = bandit_manager.BanditManager(
                b_conf,
                'file',
                profile=None,
                debug=False
            )
            
            # Discover files
            b_mgr.discover_files(python_files)
            
            # Run scan
            b_mgr.run_tests()
            
            # Get results
            results = b_mgr.get_issue_list(
                sev_level=self.min_severity,
                conf_level='LOW'
            )
            
            logger.info(f'📊 Bandit found {len(results)} issues')
            
            # Convert to our Vulnerability format
            vulnerabilities = []
            for issue in results:
                vuln = Vulnerability(
                    severity=issue.severity,
                    confidence=issue.confidence,
                    issue_text=issue.text,
                    filename=issue.fname,
                    line_number=issue.lineno,
                    code=issue.get_code(),
                    cwe_id=self._get_cwe_from_test_id(issue.test_id),
                    test_id=issue.test_id
                )
                vulnerabilities.append(vuln)
            
            logger.info(f'✅ Scan complete: {len(vulnerabilities)} vulnerabilities')
            return vulnerabilities
            
        except Exception as e:
            logger.error(f'❌ Scan failed: {e}')
            raise
    
    def _find_python_files(self, repo_path: str) -> List[str]:
        """Find all Python files in repository"""
        python_files = []
        
        for root, dirs, files in os.walk(repo_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in [
                'venv', '.venv', 'env', '.env',
                'node_modules', '.git', '__pycache__',
                '.pytest_cache', '.mypy_cache'
            ]]
            
            for file in files:
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    python_files.append(full_path)
        
        return python_files
    
    def _get_cwe_from_test_id(self, test_id: str) -> str:
        """Map Bandit test ID to CWE"""
        cwe_mapping = {
            'B201': 'CWE-502',  # pickle
            'B301': 'CWE-502',  # pickle
            'B302': 'CWE-829',  # marshal
            'B303': 'CWE-327',  # md5/sha1
            'B304': 'CWE-327',  # insecure cipher
            'B305': 'CWE-327',  # insecure cipher mode
            'B306': 'CWE-327',  # mktemp
            'B307': 'CWE-94',   # eval
            'B308': 'CWE-88',   # mark_safe
            'B309': 'CWE-1188', # httpsconnection
            'B310': 'CWE-22',   # urllib urlopen
            'B311': 'CWE-330',  # random
            'B312': 'CWE-330',  # telnetlib
            'B313': 'CWE-326',  # xml
            'B314': 'CWE-611',  # xml
            'B315': 'CWE-611',  # xml
            'B316': 'CWE-611',  # xml
            'B317': 'CWE-611',  # xml
            'B318': 'CWE-611',  # xml
            'B319': 'CWE-611',  # xml
            'B320': 'CWE-611',  # xml
            'B321': 'CWE-502',  # ftplib
            'B322': 'CWE-918',  # input
            'B323': 'CWE-330',  # unverified context
            'B324': 'CWE-327',  # hashlib
            'B401': 'CWE-78',   # import telnetlib
            'B402': 'CWE-78',   # import ftplib
            'B403': 'CWE-502',  # import pickle
            'B404': 'CWE-78',   # import subprocess
            'B405': 'CWE-611',  # import xml
            'B406': 'CWE-611',  # import xml
            'B407': 'CWE-611',  # import xml
            'B408': 'CWE-611',  # import xml
            'B409': 'CWE-611',  # import xml
            'B410': 'CWE-611',  # import xml
            'B411': 'CWE-611',  # import xml
            'B412': 'CWE-502',  # import pyghmi
            'B413': 'CWE-327',  # import pycrypto
            'B501': 'CWE-295',  # request verify=False
            'B502': 'CWE-295',  # SSL context check_hostname
            'B503': 'CWE-327',  # SSL insecure version
            'B504': 'CWE-295',  # SSL context verify_mode
            'B505': 'CWE-327',  # weak cryptographic key
            'B506': 'CWE-20',   # yaml load
            'B507': 'CWE-295',  # SSH host key verification
            'B601': 'CWE-78',   # paramiko exec
            'B602': 'CWE-78',   # subprocess shell=True
            'B603': 'CWE-78',   # subprocess without shell
            'B604': 'CWE-78',   # any other function
            'B605': 'CWE-78',   # start_process shell=True
            'B606': 'CWE-78',   # start_process no shell
            'B607': 'CWE-78',   # start process partial path
            'B608': 'CWE-89',   # SQL injection
            'B609': 'CWE-78',   # wildcard injection
            'B610': 'CWE-78',   # django extra
            'B611': 'CWE-78',   # django rawsql
            'B701': 'CWE-94',   # jinja2 autoescape
            'B702': 'CWE-79',   # mako templates
            'B703': 'CWE-94',   # django mark_safe
        }
        
        return cwe_mapping.get(test_id, 'CWE-unknown')