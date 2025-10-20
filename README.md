# CodeGuardian: Autonomous Code Remediation Agent

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock-orange)](https://aws.amazon.com/bedrock/)

CodeGuardian is an autonomous AI agent designed to detect, analyze, remediate, and validate security vulnerabilities within Python codebases. It leverages Amazon Bedrock and AgentCore to orchestrate a suite of tools, automating the entire security fix lifecycle from discovery to validation.

## Live Demonstration

A live, interactive demonstration of the CodeGuardian agent is deployed and accessible here:

**Live Demo:** [Click here to view](https://codeguardian-demo.s3.us-east-1.amazonaws.com/index.html)


---

## The Problem

Organizations face a significant and costly delay in addressing known security vulnerabilities. This remediation gap exposes them to unnecessary risk.

* **Time Lag:** The average time to identify and contain a data breach is **277 days** [¹].
* **Developer Burden:** Developers spend significant time on security tasks, with some reports estimating over **15 hours per week** dedicated to navigating and fixing security issues [²].
* **Exploitation:** A majority of successful data breaches—an estimated **60%**—exploit known vulnerabilities that have not yet been patched [³].

CodeGuardian is designed to address this gap by automating the remediation process, reducing the time to fix from days or months to minutes.

[1] IBM, "Cost of a Data Breach Report," 2024.
[2] Secure Code Warrior, "The State of Developer-Centric Security," 2023.
[3] Tenable, "Tenable Annual Threat Report," 2023.

---

## Solution Overview

CodeGuardian operates as a multi-step autonomous agent. Given a target repository, it performs the following sequence without human intervention:

1.  **Scan:** Identifies potential code quality and security issues (e.g., SQL injection, hardcoded secrets, unsafe deserialization) using static analysis.
2.  **Analyze & Reason:** For each identified issue, the agent reads the full file and analyzes the surrounding code using an Abstract Syntax Tree (AST) to understand the complete context, function, and data flow.
3.  **Generate:** Based on its analysis, the agent generates a specific, modernized code fix that remediates the issue while preserving functionality.
4.  **Validate:** The agent validates its own generated fix to ensure it is syntactically correct before proposing it as a solution.
5.  **Report:** Finally, the agent compiles a comprehensive report detailing the original issue, its reasoning, and the validated, ready-to-use code fix.

---

## System Architecture

The agent operates through a modular, tool-based architecture orchestrated by AWS Bedrock. The system is deployed using a serverless AWS stack for scalability and maintainability.

**(./docs/architecture.png)**

### Core Components

* **Frontend (AWS S3):** A static web interface, built in HTML/CSS/JavaScript, provides a live demo and user-friendly dashboard for interacting with the agent.
* **API (AWS API Gateway & Lambda):** A serverless backend that exposes the CodeGuardian agent. API Gateway handles HTTP requests, which trigger a single AWS Lambda function containing the full agent logic.
* **Agent (AWS Bedrock):** The "brain" of the operation. An Amazon Nova Lite model serves as the agent, responsible for all reasoning, analysis, and decision-making.
* **Tool Orchestration (Bedrock AgentCore):** Manages the agent's autonomous behavior and its ability to select and execute tools from a defined toolset.
* **Toolset (Python):** A collection of Python-based tools the agent can call:
    * **`SecurityScanner` (Bandit):** Scans the repository for vulnerabilities.
    * **`FileReader`:** Reads file contents to provide context to the agent.
    * **`CodeAnalyzer` (AST):** Parses code to understand its structure and scope.
    * **`SyntaxValidator`:** Validates the syntax of agent-generated code fixes.

---

## Getting Started

### Prerequisites

* An AWS Account with Bedrock model access enabled (specifically for `amazon.nova-lite-v1:0`).
* Python 3.12+
* AWS CLI configured with appropriate IAM permissions (Bedrock, Lambda, etc.).

### 1. Installation

```shell
# Clone the repository
git clone [https://github.com/rsalehin/codeGuardian.git](https://github.com/rsalehin/codeGuardian.git)
cd codeGuardian

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate
# (or `.\venv\Scripts\Activate.ps1` on Windows PowerShell)

# Install dependencies
pip install -r requirements.txt

# Create a .env file from the example
cp .env.example .env
Finally, edit the .env file to include your AWS credentials.
2. Enable Bedrock Model Access
Navigate to the AWS Bedrock Console.
In the bottom-left sidebar, click on Model access.
Click Manage model access.
Ensure that Amazon Nova Lite is enabled (Access granted).
Usage
The agent can be run programmatically or as a standalone script.
Programmatic Usage
This example demonstrates how to import and run the agent within your own application.

Python

from src.agents.autonomous_agent import AutonomousSecurityAgentfrom src.agents.bedrock_client import BedrockClient# Initialize the Bedrock client# Credentials will be loaded automatically from your .env or AWS environment
bedrock_client = BedrockClient(region='us-east-1')# Initialize the autonomous agent
agent = AutonomousSecurityAgent(
    repo_path='./vulnerable-flask-app',
    bedrock_client=bedrock_client,
    max_iterations=15
)# Run the full autonomous analysis
result = agent.analyze_repository_autonomous()# View results
print(f"Analysis Complete: {result['success']}")
print(f"Tools Used: {len(result['tools_used'])}")
print("--- Final Response ---")
print(result['final_response'])
Command-Line Interface (Example)
You can also trigger a default analysis by running the autonomous_agent module directly.

Shell

# This will load the agent and run the `analyze_repository_autonomous` method
python -m src.agents.autonomous_agent
How It Works: Autonomous Reasoning
The agent's primary capability is its autonomous, multi-step reasoning. The agent is not a simple prompt-and-response; it actively plans and executes a series of tool calls to build context and solve a complex problem.
Example Reasoning Chain:

Initial Prompt: "Analyze this repository for code quality improvements."
Agent Reasoning (Iteration 1): "I cannot analyze without knowing what's in the files. I should start by reading the main application file."
Tool Call: read_file_content(filepath='app.py')
Agent Reasoning (Iteration 2): "I have the code. I see a hardcoded secret key and a pickle.loads() call. These are code quality issues. I need to analyze the context of these lines."
Tool Call: analyze_code_context(filepath='app.py', line_number=8)
Tool Call: analyze_code_context(filepath='app.py', line_number=42)
Agent Reasoning (Iteration 3): "I have the full context. I will now generate modernized code to replace these lines, using environment variables for the secret and json.loads for data."
(Internal Generation)
Agent Reasoning (Iteration 4): "I must validate my generated code fixes before recommending them."
Tool Call: validate_python_syntax(code='import os\napp.secret_key = os.getenv(\"SECRET_KEY\")')
Tool Call: validate_python_syntax(code='import json\ndata = json.loads(user_input)')
Agent Reasoning (Iteration 5): "All my fixes are valid. I will now compile the final report for the user."
Final Response: (Generates the full report with "before" and "after" snippets).
Project Structure
codeGuardian/
├── src/
│   ├── agents/
│   │   ├── bedrock_client.py     # Wrapper for AWS Bedrock converse API
│   │   ├── security_agent.py     # (Legacy) Simple analysis agent
│   │   └── autonomous_agent.py   # Main autonomous orchestration logic
│   ├── tools/
│   │   ├── tool_definitions.py   # AgentCore tool schemas (the "menu")
│   │   ├── tool_executor.py      # Python logic for executing tools
│   │   └── security_scanner.py   # Bandit scanner integration
│   └── __init__.py
├── tests/
│   ├── test_autonomous_agent.py  # Tests autonomous behavior
│   ├── test_bedrock_client.py    # Tests Bedrock connection
│   ├── test_security_scanner.py  # Tests Bandit integration
│   └── test_tool_executor.py     # Tests tool logic
├── vulnerable-flask-app/         # Demo application for testing
├── .env.example                  # Environment variable template
├── requirements.txt
└── README.md
Testing
The project includes a comprehensive test suite using pytest. Tests cover tool execution, API client connections, and agent reasoning.

Shell

# Run the complete test suite
pytest tests/ -v
# Run tests for a specific component
pytest tests/test_security_scanner.py -v
pytest tests/test_tool_executor.py -v
pytest tests/test_autonomous_agent.py -v -s
Test Results
test_security_scanner.py::test_scan_repository        PASSED
test_security_scanner.py::test_find_python_files      PASSED
...
test_tool_executor.py::test_execute_read_file         PASSED
test_tool_executor.py::test_execute_analyze_context   PASSED
test_tool_executor.py::test_execute_validate_syntax   PASSED
...
test_autonomous_agent.py::test_agent_initialization   PASSED
test_autonomous_agent.py::test_agent_analysis_loop    PASSED

Total: 17/17 tests passing
Limitations and Future Roadmap
Current Limitations
Python Only: Analysis is currently focused on Python (Flask/Django) due to the use of Bandit and Python's AST module.
Syntactic Validation: The validate_python_syntax tool only checks if a fix is syntactically valid, not if it is logically or functionally correct.
English Only: The agent's prompts and reasoning are optimized for English.
Roadmap
Multi-Language Support: Integrate scanners and analyzers for JavaScript (ESLint), Java (SpotBugs), and Go.
Git Integration: Add tools to automatically create new branches and commit validated fixes.
Pull Request Automation: Fully automate the creation of GitHub/GitLab pull requests with the agent's report as the description.
CI/CD Pipeline Integration: Package the agent as a container or GitHub Action to run automatically on every commit.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Support and Contact
Issues: For bugs or feature requests, please use the GitHub Issues tracker.
Contact: For other inquiries, please contact R. Salehin at rsalehin@gmail.com.
Acknowledgments
This project utilizes the Bandit open-source tool for static analysis.
Built with the Amazon Bedrock platform.