# Trivy Scanner - AWS Lambda Deployment

This guide sets up Trivy as a serverless AWS Lambda function that your Streamlit Cloud app can call.

## Architecture

```
┌─────────────────┐      HTTPS API       ┌─────────────────┐
│  Streamlit      │ ──────────────────→  │  API Gateway    │
│  Cloud App      │                      │                 │
└─────────────────┘                      └────────┬────────┘
                                                  │
                                                  ▼
                                         ┌─────────────────┐
                                         │  Lambda Function │
                                         │  (Trivy Docker)  │
                                         └────────┬────────┘
                                                  │
                                                  ▼
                                         ┌─────────────────┐
                                         │  ECR / Docker   │
                                         │  Hub Images     │
                                         └─────────────────┘
```

## Quick Deploy (5 minutes)

### Step 1: Deploy CloudFormation Stack

```bash
aws cloudformation create-stack \
  --stack-name trivy-scanner-api \
  --template-body file://trivy-lambda-template.yaml \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

### Step 2: Get API Endpoint

```bash
aws cloudformation describe-stacks \
  --stack-name trivy-scanner-api \
  --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" \
  --output text
```

### Step 3: Add to Streamlit Secrets

```toml
# .streamlit/secrets.toml
TRIVY_API_URL = "https://xxxxxxxxxx.execute-api.us-east-1.amazonaws.com/prod/scan"
TRIVY_API_KEY = "your-api-key"  # Optional: Add API key for security
```

## Manual Setup

### Option A: Using AWS SAM

1. Install SAM CLI:
```bash
pip install aws-sam-cli
```

2. Deploy:
```bash
cd trivy_lambda_setup
sam build
sam deploy --guided
```

### Option B: Using Docker + Lambda

1. Build the Trivy Lambda container:
```bash
docker build -t trivy-lambda .
```

2. Push to ECR:
```bash
aws ecr create-repository --repository-name trivy-lambda
docker tag trivy-lambda:latest YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/trivy-lambda:latest
docker push YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/trivy-lambda:latest
```

3. Create Lambda function from the container image.

## API Usage

### Scan an Image

```bash
curl -X POST https://YOUR_API_ENDPOINT/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:latest"}'
```

### Response Format

```json
{
  "scanner": "Trivy",
  "image": "nginx:latest",
  "scan_time": "2025-01-15T10:30:00Z",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-6387",
      "package": "openssh",
      "severity": "CRITICAL",
      "fixed_version": "9.8p1"
    }
  ],
  "summary": {
    "total": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2
  }
}
```

## Costs

| Component | Estimated Cost |
|-----------|---------------|
| Lambda | ~$0.20 per 1000 scans |
| API Gateway | ~$3.50 per million requests |
| ECR Storage | ~$0.10/GB/month |

**Total: ~$5-10/month for typical usage**

## Security

1. **API Key Authentication**: Enable API key in API Gateway
2. **VPC**: Run Lambda in VPC for ECR access
3. **IAM**: Minimal permissions for Lambda role

## Troubleshooting

### Lambda Timeout
Increase timeout to 5 minutes for large images:
```yaml
Timeout: 300
```

### Memory Issues
Increase memory for complex scans:
```yaml
MemorySize: 2048
```

### ECR Access
Ensure Lambda has ECR permissions:
```json
{
  "Effect": "Allow",
  "Action": [
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage"
  ],
  "Resource": "*"
}
```
