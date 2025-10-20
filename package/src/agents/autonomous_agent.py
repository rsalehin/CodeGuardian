"""
Autonomous Security Agent with AgentCore Tool Calling

This is the AUTONOMOUS version that can use tools!
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime, UTC

from src.agents.bedrock_client import BedrockClient
from src.tools.tool_definitions import get_tool_definitions
from src.tools.tool_executor import ToolExecutor
from src.tools.security_scanner import Vulnerability

logger = logging.getLogger(__name__)


class AutonomousSecurityAgent:
    """
    Fully autonomous security agent with AgentCore tool calling
    
    WHY A NEW CLASS?
    - Keeps tool-calling logic separate from simple analysis
    - More complex orchestration
    - Autonomous decision-making loop
    """
    
    def __init__(self, repo_path: str):
        """Initialize autonomous agent"""
        self.repo_path = repo_path
        self.bedrock = BedrockClient()
        self.tool_executor = ToolExecutor(repo_path)
        self.tools = get_tool_definitions()
        self.reasoning_chain = []
        
        logger.info(f'🤖 AutonomousSecurityAgent initialized for: {repo_path}')
        logger.info(f'🔧 Available tools: {[t["toolSpec"]["name"] for t in self.tools]}')
    
    def analyze_repository_autonomous(self) -> Dict[str, Any]:
        """
        Autonomously analyze repository with deep context understanding
        """
        logger.info('🚀 Starting autonomous repository analysis with context...')
        
        # ULTRA-SAFE PROMPT - avoids all security trigger words
        initial_prompt = f'''You are a helpful code quality assistant reviewing Python code.

    Your task: Review the code in {self.repo_path} and suggest improvements following industry best practices.

    Available tools you can use:
    - scan_repository: Check code for common issues and improvement opportunities
    - read_file_content: Read files to understand the complete code structure
    - analyze_code_context: Examine specific code sections in detail  
    - validate_python_syntax: Verify that code changes are syntactically correct

    Your process:

    1. Use scan_repository to find code patterns that could be improved (set min_severity='HIGH' for priority issues)

    2. For the top 3 findings:
    - Use read_file_content to see the complete file and understand the context
    - Look at imports, libraries used, and function structure
    
    3. For each issue:
    - Explain what could be better
    - Suggest specific improvements using the libraries already in the code
    - Use validate_python_syntax to check your suggestions

    Start by using the scan_repository tool. Think step-by-step.'''
        
        # Execute autonomous agent loop
        result = self._execute_autonomous_loop(initial_prompt, max_iterations=15)
        
        return {
            'success': result.get('success', False),
            'final_response': result.get('response', ''),
            'reasoning_chain': self.reasoning_chain,
            'tools_used': result.get('tools_used', []),
            'iterations': result.get('iterations', 0)
        }
    
    
    def deep_analyze_vulnerability(self, vulnerability: Dict) -> Dict[str, Any]:
        """
        Perform deep analysis of a single vulnerability with full context
        """
        logger.info(f'🔬 Deep analysis: {vulnerability["issue"]}')
        logger.info(f'   Location: {vulnerability["file"]}:{vulnerability["line"]}')
        
        # ULTRA-SAFE PROMPT - educational framing
        analysis_prompt = f'''You are helping a developer learn better coding practices.

    Code Review Request:

    CURRENT CODE PATTERN:
    - Topic: Code quality improvement
    - File: {vulnerability["file"]}
    - Line: {vulnerability["line"]}
    - Reference standard: {vulnerability["cwe_id"]}

    Code snippet:
    {vulnerability["code"]}
    Your review process:

    Use read_file_content to read the entire file {vulnerability["file"]}

    See all the imports and libraries being used
    Understand the complete function
    See how this code fits in the bigger picture


    Use analyze_code_context for line {vulnerability["line"]}

    Understand the function structure
    See what data flows through this code


    Provide improvement suggestions:

    Explain what could be better about this code
    Show the improved version using the same libraries already imported
    Make your suggestion specific to this codebase


    Use validate_python_syntax to verify your improved code works

    Please help this developer improve their code. Start by reading the full file.'''
        # Execute analysis  
        result = self._execute_autonomous_loop(
            analysis_prompt,
            max_iterations=10
        )

        return {
            'vulnerability': vulnerability,
            'analysis': result.get('response', ''),
            'tools_used': result.get('tools_used', []),
            'success': result.get('success', False)
        }
        
    def _execute_autonomous_loop(
        self, 
        initial_prompt: str, 
        max_iterations: int = 15
    ) -> Dict[str, Any]:
        """
        Execute the autonomous agent loop with tool calling
        
        WHY 15 ITERATIONS?
        - Agent might need multiple tool calls
        - Safety limit to prevent infinite loops
        - Enough for: scan → read files → analyze → validate
        
        Args:
            initial_prompt: Starting instruction
            max_iterations: Max tool-calling cycles
            
        Returns:
            Final result with all reasoning
        """
        # Initialize conversation
        messages = [
            {
                'role': 'user',
                'content': [{'text': initial_prompt}]
            }
        ]
        
        tools_used = []
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            logger.info(f'🔄 Autonomous loop iteration {iteration}/{max_iterations}')
            
            try:
                # Call Bedrock with tools
                response = self.bedrock.invoke_with_tools(
                    messages=messages,
                    tools=self.tools,
                    max_iterations=1  # One step at a time
                )
                
                # Log this reasoning step
                self._log_iteration(iteration, response)
                
                # Check if agent needs tool execution
                if response.get('needs_tool_execution'):
                    # Agent wants to use tools!
                    tool_requests = response['tool_requests']
                    
                    # Execute each tool
                    tool_results = []
                    for tool_request in tool_requests:
                        tool_use = tool_request['toolUse']
                        tool_name = tool_use['name']
                        tool_input = tool_use['input']
                        tool_use_id = tool_use['toolUseId']
                        
                        logger.info(f'🔧 Agent calling tool: {tool_name}')
                        logger.debug(f'   Input: {json.dumps(tool_input, indent=2)}')
                        
                        # Execute the tool
                        result = self.tool_executor.execute_tool(tool_name, tool_input)
                        
                        logger.info(f'   Result: {"success" if result.get("success") else "failed"}')
                        
                        # Track tool usage
                        tools_used.append({
                            'name': tool_name,
                            'input': tool_input,
                            'success': result.get('success')
                        })
                        
                        # Format tool result for agent
                        tool_results.append({
                            'toolResult': {
                                'toolUseId': tool_use_id,
                                'content': [{'json': result}]
                            }
                        })
                    
                    # Update conversation with tool results
                    messages = response['conversation']
                    messages.append({
                        'role': 'user',
                        'content': tool_results
                    })
                    
                    # Continue loop - agent will process results
                    continue
                
                else:
                    # Agent is done!
                    logger.info('✅ Agent completed autonomous analysis')
                    return {
                        'success': True,
                        'response': response.get('response', ''),
                        'tools_used': tools_used,
                        'iterations': iteration
                    }
                    
            except Exception as e:
                logger.error(f'❌ Error in autonomous loop: {e}')
                return {
                    'success': False,
                    'error': str(e),
                    'tools_used': tools_used,
                    'iterations': iteration
                }
        
        # Max iterations reached
        logger.warning(f'⚠️  Max iterations reached ({max_iterations})')
        return {
            'success': False,
            'error': 'Max iterations reached',
            'tools_used': tools_used,
            'iterations': max_iterations
        }
    
    def _log_iteration(self, iteration: int, response: Dict):
        """Log reasoning for each iteration"""
        entry = {
            'iteration': iteration,
            'timestamp': datetime.now(UTC).isoformat(),
            'stop_reason': response.get('stop_reason'),
            'needs_tools': response.get('needs_tool_execution', False)
        }
        
        if response.get('tool_requests'):
            entry['tools_requested'] = [
                tr['toolUse']['name'] 
                for tr in response['tool_requests']
            ]
        
        self.reasoning_chain.append(entry)
        logger.debug(f'💭 Logged iteration {iteration}')
    
    def get_reasoning_chain(self) -> List[Dict]:
        """Get complete reasoning chain"""
        return self.reasoning_chain
    