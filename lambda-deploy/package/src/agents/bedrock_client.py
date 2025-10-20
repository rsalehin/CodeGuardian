"""
Bedrock API Client for CodeGuardian
"""

import boto3
import json
import logging
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BedrockClient:
    """Wrapper for Amazon Bedrock API calls"""
    
    def __init__(self, region: str = 'us-east-1', model_id: str = None):
        """Initialize Bedrock client"""
        self.region = region
        self.model_id = model_id or 'amazon.nova-lite-v1:0'
        
        try:
            self.bedrock_runtime = boto3.client(
                service_name='bedrock-runtime',
                region_name=region
            )
            logger.info(f'✅ Bedrock client initialized - Region: {region}, Model: {self.model_id}')
        except Exception as e:
            logger.error(f'❌ Failed to initialize Bedrock client: {e}')
            raise
    
    def invoke_model(
        self, 
        prompt: str, 
        max_tokens: int = 4096, 
        temperature: float = 0.7,
        system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Invoke Bedrock model - works with both DeepSeek and other models"""
        try:
            # Build full prompt
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            
            # Check if DeepSeek (needs legacy API)
            if 'deepseek' in self.model_id.lower():
                logger.info('🤖 Using legacy API for DeepSeek-R1')
                
                request_body = json.dumps({
                    "prompt": full_prompt,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                })
                
                response = self.bedrock_runtime.invoke_model(
                    modelId=self.model_id.strip(),  # Strip any spaces!
                    body=request_body
                )
                
                response_body = json.loads(response['body'].read())
                response_text = response_body.get('outputs', [{}])[0].get('text', '')
                
                # Handle <think> tags
                if '<think>' in response_text and '</think>' in response_text:
                    parts = response_text.split('</think>')
                    if len(parts) > 1:
                        thinking = response_text.split('<think>')[1].split('</think>')[0]
                        logger.info(f'🧠 Reasoning: {thinking[:100]}...')
                        response_text = parts[1].strip()
                
                usage = {
                    'inputTokens': response_body.get('usage', {}).get('input_tokens', 0),
                    'outputTokens': response_body.get('usage', {}).get('output_tokens', 0),
                    'totalTokens': response_body.get('usage', {}).get('total_tokens', 0)
                }
            
            else:
                # Use converse API for Nova, Claude
                messages = [{
                    'role': 'user',
                    'content': [{'text': full_prompt}]
                }]
                
                response = self.bedrock_runtime.converse(
                    modelId=self.model_id,
                    messages=messages,
                    inferenceConfig={
                        'maxTokens': max_tokens,
                        'temperature': temperature,
                        'topP': 0.9
                    }
                )
                
                response_text = response['output']['message']['content'][0]['text']
                usage = response.get('usage', {})
            
            logger.info(f'✅ Model invoked successfully')
            logger.info(f'   Tokens: {usage.get("totalTokens", 0)}')
            
            return {
                'response': response_text,
                'usage': usage,
                'stop_reason': 'end_turn',
                'model_id': self.model_id,
                'filtered': False
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f'❌ Bedrock API error: {error_code} - {error_message}')
            raise RuntimeError(f'Bedrock error: {error_code} - {error_message}')
        except Exception as e:
            logger.error(f'❌ Unexpected error: {e}')
            raise
    
    def invoke_with_tools(
        self,
        messages: List[Dict],
        tools: List[Dict],
        max_iterations: int = 10
    ) -> Dict[str, Any]:
        """Invoke model with tool calling capability (AgentCore)"""
        iteration = 0
        conversation = messages.copy()
        
        logger.info(f'🤖 Starting tool-enabled conversation (max {max_iterations} iterations)')
        
        while iteration < max_iterations:
            iteration += 1
            logger.info(f'🔄 Iteration {iteration}/{max_iterations}')
            
            try:
                response = self.bedrock_runtime.converse(
                    modelId=self.model_id,
                    messages=conversation,
                    inferenceConfig={
                        'maxTokens': 4096,
                        'temperature': 0.7,
                        'topP': 0.9
                    },
                    toolConfig={'tools': tools}
                )
                
                stop_reason = response.get('stopReason')
                logger.info(f'   Stop reason: {stop_reason}')
                
                if stop_reason == 'end_turn':
                    logger.info('✅ Agent completed task')
                    final_message = response['output']['message']['content']
                    
                    final_text = ''
                    for content in final_message:
                        if 'text' in content:
                            final_text += content['text']
                    
                    return {
                        'response': final_text,
                        'usage': response.get('usage', {}),
                        'stop_reason': stop_reason,
                        'iterations': iteration,
                        'conversation': conversation
                    }
                
                elif stop_reason == 'tool_use':
                    logger.info('🔧 Agent requesting tool use')
                    
                    assistant_message = response['output']['message']
                    conversation.append(assistant_message)
                    
                    tool_uses = [
                        content for content in assistant_message['content']
                        if 'toolUse' in content
                    ]
                    
                    logger.info(f'   Agent wants to call {len(tool_uses)} tool(s)')
                    
                    return {
                        'response': None,
                        'tool_requests': tool_uses,
                        'stop_reason': stop_reason,
                        'conversation': conversation,
                        'needs_tool_execution': True
                    }
                
                else:
                    logger.warning(f'⚠️  Unexpected stop reason: {stop_reason}')
                    
                    if stop_reason == 'content_filtered' and iteration == 1:
                        logger.info('🔄 Content filtered, retrying...')
                        conversation.append({
                            'role': 'user', 
                            'content': [{'text': 'Please use the scan_repository tool.'}]
                        })
                        continue
                    
                    return {
                        'response': f'Unable to complete: {stop_reason}',
                        'stop_reason': stop_reason,
                        'conversation': conversation,
                        'error': True
                    }
                    
            except Exception as e:
                logger.error(f'❌ Error in tool-enabled conversation: {e}')
                raise
        
        logger.warning(f'⚠️  Max iterations ({max_iterations}) reached')
        return {
            'response': 'Max iterations reached',
            'stop_reason': 'max_iterations',
            'conversation': conversation
        }

    def test_connection(self) -> bool:
        """Test if Bedrock connection works"""
        try:
            response = self.invoke_model(
                prompt='Say hello in exactly 3 words.',
                max_tokens=50
            )
            logger.info('✅ Bedrock connection test successful')
            return True
        except Exception as e:
            logger.error(f'❌ Bedrock connection test failed: {e}')
            return False
