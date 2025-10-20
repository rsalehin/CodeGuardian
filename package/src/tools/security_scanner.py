"""
Security scanning tool integration using Bandit

This module provides a clean interface to Bandit security scanner,
converting its JSON output into structured Python objects that our
agent can reason about.
"""

from dataclasses import dataclass
from typing import List, Optional
import subprocess
import json
import tempfile
from pathlib import Path


@dataclass
class Vulnerability:
    """
    Represents a single security vulnerability found in code
    
    Why dataclass? It auto-generates __init__, __repr__, and __eq__
    This makes our code cleaner and easier to test.
    """
    severity: str          # HIGH, MEDIUM, LOW
    confidence: str        # HIGH, MEDIUM, LOW
    issue_text: str        # Human-readable description
    filename: str          # Relative path to vulnerable file
    line_number: int       # Line where vulnerability exists
    code: str              # The actual vulnerable code snippet
    cwe_id: str           # Common Weakness Enumeration ID (e.g., CWE-89)
    test_id: str          # Bandit's test identifier (e.g., B608)
    
    def __str__(self):
        return f"[{self.severity}] {self.issue_text} at {self.filename}:{self.line_number}"
    
    @property
    def is_critical(self) -> bool:
        '''Check if vulnerability is critical (HIGH severity + HIGH confidence)'''
        return self.severity == 'HIGH' and self.confidence == 'HIGH'
    
    @property
    def is_high_priority(self) -> bool:
        '''Check if vulnerability should be fixed first'''
        return self.severity in ['HIGH', 'MEDIUM']


class SecurityScanner:
    '''Integrates Bandit security scanner for Python code analysis
    Integrates Bandit security scanner for Python code analysis
    
    Why a class? 
    - Encapsulates all scanner logic in one place
    - Can be easily mocked for testing
    - Allows configuration (e.g., different severity thresholds)
    '''
    
    def __init__(self, min_severity: str = 'LOW'):
        """
        Initialize scanner
        
        Args:
            min_severity: Minimum severity to report (LOW, MEDIUM, HIGH)
        """
        self.min_severity = min_severity
        self.severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
    
    def scan_repository(self, repo_path: str) -> List[Vulnerability]:
        """
        Scan a repository for security vulnerabilities
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            List of Vulnerability objects found
            
        Why this approach?
        - We run Bandit as a subprocess (it's an external tool)
        - Output to temp file (cleaner than capturing stdout)
        - Parse JSON into our clean Vulnerability objects
        - Filter by severity threshold
        """
        repo_path = Path(repo_path).resolve()
        
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        
        # Create temporary file for Bandit output
        # Why temp file? Keeps filesystem clean, auto-cleanup
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
            output_file = tmp.name
        
        try:
            # Run Bandit scan
            # Why these flags?
            # -r: Recursive scan
            # -f json: Machine-readable output
            # -o: Output to file
            # --exit-zero: Don't fail on vulnerabilities (we want to process them)
            result = subprocess.run(
                [
                    'bandit',
                    '-r', str(repo_path),
                    '-x', 'venv, node_modules, migrations',
                    '-f', 'json',
                    '-o', output_file,
                    '--exit-zero'  # Don't exit with error code on findings
                ],
                capture_output=True,
                text=True,
                timeout=180  # Safety: don't hang forever
            )
            
            # Read and parse results
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert to Vulnerability objects
            vulnerabilities = self._parse_bandit_output(data)
            
            # Filter by severity threshold
            filtered = self._filter_by_severity(vulnerabilities)
            
            return filtered
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Bandit scan timed out after 60 seconds")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Bandit output: {e}")
        finally:
            # Cleanup temp file
            Path(output_file).unlink(missing_ok=True)
    
    def _parse_bandit_output(self, data: dict) -> List[Vulnerability]:
        """
        Parse Bandit JSON output into Vulnerability objects
        
        Why separate method?
        - Single Responsibility Principle (each method does one thing)
        - Easier to test
        - Easier to modify if Bandit output format changes
        """
        vulnerabilities = []
        
        for result in data.get('results', []):
            vuln = Vulnerability(
                severity=result.get('issue_severity', 'UNKNOWN'),
                confidence=result.get('issue_confidence', 'UNKNOWN'),
                issue_text=result.get('issue_text', 'No description'),
                filename=result.get('filename', 'unknown'),
                line_number=result.get('line_number', 0),
                code=result.get('code', '').strip(),
                cwe_id=result.get('issue_cwe', {}).get('id', 'UNKNOWN') if isinstance(result.get('issue_cwe'), dict) else 'UNKNOWN',
                test_id=result.get('test_id', 'UNKNOWN')
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _filter_by_severity(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """
        Filter vulnerabilities by minimum severity
        
        Why filter?
        - LOW severity issues might be noise
        - Agent should focus on critical issues first
        - Makes demo more impressive (shows prioritization)
        """
        min_level = self.severity_levels.get(self.min_severity, 0)
        
        return [
            v for v in vulnerabilities
            if self.severity_levels.get(v.severity, 0) >= min_level
        ]
    
    def get_summary(self, vulnerabilities: List[Vulnerability]) -> dict:
        """
        Generate summary statistics
        
        Why?
        - Useful for logging and reporting
        - Helps agent understand the scope of work
        - Makes demo output more professional
        """
        summary = {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v.is_critical]),
            'high': len([v for v in vulnerabilities if v.severity == 'HIGH']),
            'medium': len([v for v in vulnerabilities if v.severity == 'MEDIUM']),
            'low': len([v for v in vulnerabilities if v.severity == 'LOW']),
        }
        return summary
