"""
Local Lambda Test Script - IMPROVED VERSION

This handles Python import paths correctly!
"""

import sys
import json
import os
from pathlib import Path

print("🧪 CodeGuardian Lambda - Local Test")
print("=" * 80)

# Get current directory
current_dir = Path(__file__).parent
print(f"\n📂 Current directory: {current_dir}")

# Check if lambda_function.py exists
lambda_file = current_dir / "lambda_function.py"
package_lambda = current_dir / "package" / "lambda_function.py"

if lambda_file.exists():
    print(f"✅ Found lambda_function.py in: {current_dir}")
    lambda_location = str(current_dir)
elif package_lambda.exists():
    print(f"✅ Found lambda_function.py in: {current_dir / 'package'}")
    lambda_location = str(current_dir / "package")
else:
    print(f"❌ Cannot find lambda_function.py!")
    print(f"   Checked: {lambda_file}")
    print(f"   Checked: {package_lambda}")
    print("\n📁 Files in current directory:")
    for item in current_dir.iterdir():
        print(f"   - {item.name}")
    sys.exit(1)

# Add correct paths
sys.path.insert(0, lambda_location)
sys.path.insert(0, str(current_dir / "package" / "src"))
sys.path.insert(0, str(current_dir / "package"))
sys.path.insert(0, str(current_dir / "src"))

print(f"\n🔧 Python paths configured:")
for i, path in enumerate(sys.path[:5], 1):
    print(f"   {i}. {path}")

# Set environment
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

# Import Lambda function
print("\n📦 Importing Lambda function...")
try:
    from lambda_function import lambda_handler
    print("✅ Lambda function imported successfully!")
except Exception as e:
    print(f"❌ Import failed: {e}")
    print("\n🔍 Debug info:")
    print(f"   Python version: {sys.version}")
    print(f"   Current working directory: {os.getcwd()}")
    print(f"   sys.path: {sys.path[:3]}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Create test event
test_event = {
    "body": json.dumps({
        "repository": "flask"
    })
}

# Mock Lambda context
class MockContext:
    function_name = "CodeGuardian-Agent-Test"
    memory_limit_in_mb = 1024
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789:function:test"
    aws_request_id = "test-request-123"
    
    def get_remaining_time_in_millis(self):
        return 900000

print("\n🚀 Running Lambda function...")
print(f"📁 Testing with repository: flask")
print("=" * 80)

# Run the function!
try:
    result = lambda_handler(test_event, MockContext())
    
    print("\n" + "=" * 80)
    print("📊 RESULTS")
    print("=" * 80)
    
    print(f"\n✅ Status Code: {result['statusCode']}")
    
    if result['statusCode'] == 200:
        body = json.loads(result['body'])
        print(f"✅ Success: {body.get('success')}")
        print(f"📊 Repository: {body.get('repository')}")
        
        if 'stats' in body:
            stats = body['stats']
            print(f"\n📈 Statistics:")
            print(f"   Vulnerabilities: {stats.get('total_vulnerabilities')}")
            print(f"   Tools Called: {stats.get('tools_called')}")
            print(f"   Files Read: {stats.get('files_read')}")
        
        if 'vulnerabilities' in body:
            vulns = body['vulnerabilities']
            print(f"\n🔒 Found {len(vulns)} vulnerabilities:")
            for i, vuln in enumerate(vulns[:3], 1):
                print(f"   {i}. {vuln.get('title')} [{vuln.get('severity')}]")
        
        if 'error' in body:
            print(f"\n⚠️  Error in response: {body.get('error')}")
            if 'traceback' in body:
                print(f"\n🐛 Traceback:\n{body.get('traceback')}")
        
        print("\n✅ LOCAL TEST COMPLETED!")
        
    else:
        print(f"❌ Error response")
        body_text = result['body'][:1000] if len(result['body']) > 1000 else result['body']
        print(f"Body: {body_text}")
        
except Exception as e:
    print("\n" + "=" * 80)
    print("❌ TEST FAILED")
    print("=" * 80)
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 80)
print("🎉 Local testing complete!")
print("=" * 80)