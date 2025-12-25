# ☁️ Cloud Compliance Canvas | Enterprise AWS Governance Platform

AI-Powered Multi-Cloud Compliance, FinOps, and Security Orchestration

## 🎯 Enterprise Features

- ✓ Executive Dashboard with Real-Time KPIs
- ✓ Multi-Account Lifecycle Management (Onboarding/Offboarding)
- ✓ AI-Powered Threat Detection & Automated Remediation
- ✓ Advanced FinOps with Predictive Analytics & Chargeback
- ✓ Compliance Framework Mapping (SOC 2, PCI-DSS, HIPAA, GDPR, ISO 27001)
- ✓ Policy as Code Engine with OPA Integration
- ✓ AWS Control Tower Integration
- ✓ Demo/Live Mode Toggle
- ✓ **NEW:** Unified Remediation Dashboard (single pane of glass)
- ✓ **NEW:** Kubernetes API integration for EKS remediation

## 📁 Project Structure

```
compliancfinops_clean/
├── streamlit_app.py                              # Main application (560 KB)
├── enterprise_module.py                          # Enterprise auth, Control Tower, RBAC (83 KB)
├── account_lifecycle_enhanced.py                 # Account provisioning & templates (100 KB)
├── eks_vulnerability_enterprise_complete.py      # EKS vulnerability management (85 KB)
├── scp_policy_engine.py                          # Service Control Policies engine (63 KB)
├── batch_remediation_production.py               # Batch remediation workflows (60 KB)
├── finops_module_enhanced_complete.py            # FinOps dashboard & analytics (51 KB)
├── eks_container_vulnerability_module.py         # Container scanning (48 KB)
├── windows_server_remediation_MERGED_ENHANCED.py # Windows remediation scripts (48 KB)
├── linux_distribution_remediation_MERGED_ENHANCED.py # Linux remediation scripts (46 KB)
├── scp_scene_5_enhanced.py                       # SCP policy UI scene (41 KB)
├── unified_remediation_dashboard.py              # ⭐ NEW: Single pane remediation (37 KB)
├── ai_threat_scene_6_PRODUCTION.py               # AI threat analysis (36 KB)
├── pipeline_simulator.py                         # CI/CD pipeline simulator (31 KB)
├── code_generation_production.py                 # AI code generation (24 KB)
├── finops_scene_7_complete.py                    # FinOps predictive scene (24 KB)
├── eks_remediation_complete.py                   # ⭐ NEW: K8s API remediation (21 KB)
├── ai_configuration_assistant_complete.py        # AI configuration assistant (20 KB)
├── requirements.txt                              # Python dependencies
├── STREAMLIT_CLOUD_QUICKSTART.md                 # Deployment guide
└── README.md                                     # This file
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure AWS Credentials

Create `.streamlit/secrets.toml`:

```toml
[aws]
access_key_id = "YOUR_ACCESS_KEY"
secret_access_key = "YOUR_SECRET_KEY"
region = "us-east-1"

[anthropic]
api_key = "YOUR_ANTHROPIC_API_KEY"
```

### 3. Run the Application

```bash
streamlit run streamlit_app.py
```

## 🔧 Configuration

### Demo Mode vs Live Mode

- **Demo Mode**: Uses sample data for demonstration (no AWS credentials required)
- **Live Mode**: Connects to your actual AWS accounts

Toggle between modes in the sidebar.

### AWS Services Required

For full Live Mode functionality, enable these services in your AWS account:

- AWS Organizations (for multi-account management)
- AWS Control Tower (for governance)
- AWS Security Hub (for compliance findings)
- AWS Config (for resource compliance)
- AWS GuardDuty (for threat detection)
- AWS Inspector (for vulnerability scanning)
- AWS Cost Explorer (for FinOps)

### IAM Permissions

The IAM user/role needs these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:List*",
        "organizations:Describe*",
        "securityhub:Get*",
        "securityhub:List*",
        "config:Describe*",
        "guardduty:Get*",
        "guardduty:List*",
        "inspector2:List*",
        "ce:GetCostAndUsage",
        "ce:GetCostForecast",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🔐 Enterprise Authentication

Default demo accounts (password: `demo123`):

| Email | Role | Access |
|-------|------|--------|
| admin@example.com | Global Admin | Full access |
| cfo@example.com | CFO/FinOps | FinOps, Reports |
| ciso@example.com | CISO | Security, Compliance |
| cto@example.com | CTO | Control Tower, Accounts |

## 📊 Key Dashboards

1. **Unified Compliance** - Overall security posture
2. **Security Findings** - Security Hub integration
3. **Tech Guardrails** - SCPs, OPA, KICS
4. **AI Remediation** - Automated threat response
5. **FinOps** - Cost management & optimization
6. **Account Lifecycle** - Provisioning & offboarding

## 🐛 Troubleshooting

### "UnrecognizedClientException" Error

This means AWS credentials are invalid or expired. Check:
1. Your `secrets.toml` has correct credentials
2. The region matches where your services are enabled
3. Credentials have not expired

### 0% Compliance Score

This can happen when:
1. Security Hub is not enabled in the configured region
2. AWS Config has no rules configured
3. The app is in Live Mode but not connected

Solution: Enable Demo Mode to see sample data, or verify AWS services are properly configured.

## 📝 Version

Enterprise Edition v6.0 | Demo/Live Mode | AWS re:Invent 2025 Ready

## 📄 License

Proprietary - Future Minds Enterprise Platform
