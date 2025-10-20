Write-Host "🧪 Testing SAM Local API..."
Write-Host ""

# Prepare request
$body = @{
    repository = "flask"
} | ConvertTo-Json

Write-Host "📤 Sending POST request to http://127.0.0.1:3000/analyze"
Write-Host "📦 Body: $body"
Write-Host ""

try {
    $response = Invoke-RestMethod `
        -Uri "http://127.0.0.1:3000/analyze" `
        -Method POST `
        -Body $body `
        -ContentType "application/json"
    
    Write-Host "✅ SUCCESS!"
    Write-Host ""
    Write-Host "📊 Response:"
    Write-Host "Success: $($response.success)"
    Write-Host "Repository: $($response.repository)"
    Write-Host "Vulnerabilities: $($response.stats.total_vulnerabilities)"
    Write-Host "Tools Called: $($response.stats.tools_called)"
    Write-Host ""
    
    # Show full response
    Write-Host "📝 Full Response:"
    $response | ConvertTo-Json -Depth 10
    
} catch {
    Write-Host "❌ Error: $_"
    Write-Host $_.Exception.Message
}
