"""
Security Scanner - Lambda Compatible Version

Uses Bandit Python API instead of CLI command
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
        self.scan_results = []
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
            
            self.scan_results = vulnerabilities
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
    
    def get_summary(self, vulnerabilities=None) -> dict:
        """
        Get scan summary
        
        Args:
            vulnerabilities: Optional list of vulnerabilities to summarize.
                           If None, uses self.scan_results
        """
        vulns = vulnerabilities if vulnerabilities is not None else self.scan_results
        
        if not vulns:
            return {
                'total_issues': 0,
                'by_severity': {},
                'by_confidence': {}
            }
        
        by_severity = {}
        by_confidence = {}
        
        for vuln in vulns:
            by_severity[vuln.severity] = by_severity.get(vuln.severity, 0) + 1
            by_confidence[vuln.confidence] = by_confidence.get(vuln.confidence, 0) + 1
        
        return {
            'total_issues': len(vulns),
            'by_severity': by_severity,
            'by_confidence': by_confidence
        }
    
    def _get_cwe_from_test_id(self, test_id: str) -> str:
        """Map Bandit test ID to CWE"""
        cwe_mapping = {
            'B201': 'CWE-502',
            'B301': 'CWE-502',
            'B302': 'CWE-829',
            'B303': 'CWE-327',
            'B304': 'CWE-327',
            'B305': 'CWE-327',
            'B306': 'CWE-327',
            'B307': 'CWE-94',
            'B308': 'CWE-88',
            'B309': 'CWE-1188',
            'B310': 'CWE-22',
            'B311': 'CWE-330',
            'B312': 'CWE-330',
            'B313': 'CWE-326',
            'B314': 'CWE-611',
            'B315': 'CWE-611',
            'B316': 'CWE-611',
            'B317': 'CWE-611',
            'B318': 'CWE-611',
            'B319': 'CWE-611',
            'B320': 'CWE-611',
            'B321': 'CWE-502',
            'B322': 'CWE-918',
            'B323': 'CWE-330',
            'B324': 'CWE-327',
            'B401': 'CWE-78',
            'B402': 'CWE-78',
            'B403': 'CWE-502',
            'B404': 'CWE-78',
            'B405': 'CWE-611',
            'B406': 'CWE-611',
            'B407': 'CWE-611',
            'B408': 'CWE-611',
            'B409': 'CWE-611',
            'B410': 'CWE-611',
            'B411': 'CWE-611',
            'B412': 'CWE-502',
            'B413': 'CWE-327',
            'B501': 'CWE-295',
            'B502': 'CWE-295',
            'B503': 'CWE-327',
            'B504': 'CWE-295',
            'B505': 'CWE-327',
            'B506': 'CWE-20',
            'B507': 'CWE-295',
            'B601': 'CWE-78',
            'B602': 'CWE-78',
            'B603': 'CWE-78',
            'B604': 'CWE-78',
            'B605': 'CWE-78',
            'B606': 'CWE-78',
            'B607': 'CWE-78',
            'B608': 'CWE-89',
            'B609': 'CWE-78',
            'B610': 'CWE-78',
            'B611': 'CWE-78',
            'B701': 'CWE-94',
            'B702': 'CWE-79',
            'B703': 'CWE-94',
        }
        
        return cwe_mapping.get(test_id, 'CWE-unknown')