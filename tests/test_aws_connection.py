"""
Test AWS connection and Bedrock access
"""
import boto3
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_aws_connection():
    """Test basic AWS connection"""
    print("Testing AWS Connection...")
    
    try:
        # Create bedrock client
        bedrock = boto3.client(
            'bedrock',
            region_name=os.getenv('AWS_REGION', 'us-east-1')
        )
        
        # List models
        response = bedrock.list_foundation_models()
        
        print(f"✅ Successfully connected to AWS Bedrock")
        print(f"✅ Found {len(response['modelSummaries'])} models")
        
        # Check for Nova models
        nova_models = [m for m in response['modelSummaries'] if 'nova' in m['modelId'].lower()]
        print(f"✅ Found {len(nova_models)} Nova models")
        
        for model in nova_models:
            print(f"   - {model['modelId']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_aws_connection()
    exit(0 if success else 1)
