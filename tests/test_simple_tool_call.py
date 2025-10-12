"""
Simple test to verify tool calling works.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agents.bedrock_client import BedrockClient
from src.tools.tool_definitions import get_tool_definitions


def test_simple_tool_call():
    """
    Simplest possible tool calling test.

    WHY?
    - Isolates the tool calling mechanism
    - Helps debug content filter issues
    - Tests with minimal prompt
    """
    print('\n' + '=' * 80)
    print('🧪 SIMPLE TOOL CALLING TEST')
    print('=' * 80)

    client = BedrockClient()
    tools = get_tool_definitions()

    # ULTRA-SIMPLE prompt
    messages = [{
        'role': 'user',
        'content': [{
            'text': '''You have access to a tool called scan_repository.

Please use it to scan the current directory.

Call scan_repository with:
- repo_path: "."
- min_severity: "HIGH"

Just call the tool now.'''
        }]
    }]

    print('\n📤 Sending simple tool request...')

    response = client.invoke_with_tools(
        messages=messages,
        tools=tools,
        max_iterations=1
    )

    print(f'\n📥 Response:')
    print(f'Stop reason: {response.get("stop_reason")}')
    print(f'Needs tool execution: {response.get("needs_tool_execution", False)}')

    if response.get('tool_requests'):
        print('✅ Tool requested!')
        for tr in response['tool_requests']:
            print(f'   - {tr["toolUse"]["name"]}')
    else:
        print('❌ No tool requested')
        print(f'Response: {response.get("response", "No response")}')

    print('=' * 80)

    # This test is informational — doesn't assert
    # Just shows us what's happening


if __name__ == '__main__':
    test_simple_tool_call()
