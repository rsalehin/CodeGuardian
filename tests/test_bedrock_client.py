"""
Tests for Bedrock client

WHY TEST THIS?
- Bedrock is external service - network can fail
- AWS permissions can be tricky
- Want to catch issues before building on top of it
"""

import pytest
from src.agents.bedrock_client import BedrockClient


def test_bedrock_initialization():
    """Test that client can be initialized"""
    client = BedrockClient()
    assert client.model_id == 'us.amazon.nova-lite-v1:0'
    assert client.region == 'us-east-1'
    print('✅ Client initialized successfully')


def test_bedrock_connection():
    """
    Test actual connection to Bedrock
    
    Why this test?
    - Validates AWS credentials work
    - Confirms model access is granted
    - Ensures network connectivity
    """
    client = BedrockClient()
    
    # Simple test prompt
    response = client.invoke_model(
        prompt='What is 2+2? Reply with only the number.',
        max_tokens=50
    )
    
    # Verify response structure
    assert 'response' in response
    assert 'usage' in response
    assert response['usage']['totalTokens'] > 0
    
    # Verify actual response
    assert '4' in response['response']
    
    print(f'\n✅ Bedrock connection successful!')
    print(f'Response: {response["response"]}')
    print(f'Tokens used: {response["usage"]["totalTokens"]}')


def test_bedrock_with_system_prompt():
    """
    Test using system prompts
    
    Why important?
    - System prompts control agent behavior
    - This is how we'll tell the agent to be a security expert
    """
    client = BedrockClient()
    
    response = client.invoke_model(
        prompt='Analyze this vulnerability: SQL injection in login form',
        system_prompt='You are a cybersecurity expert. Be concise.',
        max_tokens=200
    )
    
    assert 'response' in response
    assert len(response['response']) > 0
    
    print(f'\n✅ System prompt test passed')
    print(f'Response preview: {response["response"][:150]}...')


def test_connection_helper():
    """Test the connection test helper method"""
    client = BedrockClient()
    result = client.test_connection()
    assert result == True
    print('✅ Connection test helper works')


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
