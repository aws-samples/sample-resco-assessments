# ReSCO Assessments

## Overview
This monorepo contains a collection of tools and frameworks for performing ReSCO (Resilience, Security, and Cost Optimization) assessments across different types of workloads and infrastructures. It uses AWS serverless services to gather the data from the control plane and provide a list of assessments with the sevrity level and recommended actions.

ReSCO assessments help organizations evaluate and improve their:
- **Resilience**: System reliability, fault tolerance, and disaster recovery capabilities
- **Security**: Security posture, compliance, and risk management
- **Cost Optimization**: Resource utilization, cost efficiency, and optimization opportunities

## Assessment Modules 

| Module | Description | Lambda Functions | Status |
|--------|-------------|------------------|--------|
| [resco-aiml-assessment](./resco-aiml-assessment) | AI/ML workload assessments | Bedrock Lambda, SageMaker Lambda | ✅ Active |
| [resco-security-assessment](./resco-security-assessment) | General security assessments | EC2 Lambda, RDS Lambda, Lambda Lambda, VPC Lambda | 🚧 Planned |
| [resco-resilience-assessment](./resco-resilience-assessment) | Resilience & DR assessments | Backup Lambda, HA Lambda, DR Lambda, FT Lambda | 📋 Planned |
| [resco-cost-assessment](./resco-cost-assessment) | Cost optimization assessments | Utilization Lambda, Optimization Lambda, Rightsizing Lambda, Waste Lambda | 📋 Planned |

## Prerequisites
- Python 3.12+ - [Install Python](https://www.python.org/downloads/)
- SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community)

## Deployment Overview

Clone the Repository
```bash
git clone https://github.com/your-username/resco-assessments.git
cd resco-assessments/deployment
```
You will see 1-resco-member-roles.yaml and 2-resco-multi-account-assessment.yaml file in the deployment folder. 

For single account deployment, skip to [Step 2: Deploy Central Infrastructure](#step-2-deploy-central-infrastructure) and choose Single Account Mode.
For multi account deployment, proceed with all the below steps.

The deployment follows a two-phase approach:

**Phase 1: Infrastructure Setup**
1. **Member Account Roles**: Deploy `1-resco-member-roles.yaml` via StackSets to all target accounts
2. **Central Infrastructure**: Deploy `2-resco-multi-account-assessment.yaml` in management account

**Phase 2: Assessment Execution (Automatic)**
3. **CodeBuild Orchestration**: Automatically triggered after central stack creation
4. **Module Deployment**: Conditionally deploys assessment modules to each account
5. **Assessment Execution**: Step Functions orchestrate service-specific Lambda functions
6. **Results Consolidation**: Multi-account, multi-module report generation

### Two-Phase Deployment Process

## Phase 1: Infrastructure Setup

### Step 1: Deploy Member Roles (StackSets)

Deploy `1-resco-member-roles.yaml` to all target accounts using CloudFormation StackSets.

#### Prerequisites
- AWS Organizations setup with management account access
- StackSets service-linked roles configured

#### AWS Console Deployment
1. Navigate to **CloudFormation** > **StackSets**
2. Create StackSet with `1-resco-member-roles.yaml`
3. Set `ReSCOAccountID` parameter to your management account ID
4. Deploy to target organizational units or accounts

#### AWS CLI Deployment
```bash
# Create and deploy StackSet
aws cloudformation create-stack-set \
  --stack-set-name resco-aiml-member-roles \
  --template-body file://1-resco-member-roles.yaml \
  --parameters ParameterKey=ReSCOAccountID,ParameterValue=123456789012 \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation create-stack-instances \
  --stack-set-name resco-aiml-member-roles \
  --deployment-targets OrganizationalUnitIds=ou-root-xxxxxxxxxx \
  --regions us-east-1
```

### Step 2: Deploy Central Infrastructure

Deploy `2-resco-multi-account-assessment.yaml` in your central management account.

#### AWS Console Deployment
1. Navigate to **CloudFormation** > **Stacks**
2. Create stack with `2-resco-multi-account-assessment.yaml`
3. Configure assessment module parameters
4. Stack creation automatically triggers CodeBuild

#### AWS CLI Deployment
```bash
aws cloudformation create-stack \
  --stack-name resco-aiml-multi-account \
  --template-body file://2-resco-multi-account-assessment.yaml \
  --parameters \
    ParameterKey=MultiAccountScan,ParameterValue=true \
    ParameterKey=DEPLOY_AIML_ASSESSMENT,ParameterValue=true \
  --capabilities CAPABILITY_NAMED_IAM
```

## Phase 2: Assessment Execution (Automatic)

After central stack creation:
1. **Lambda Trigger** automatically starts CodeBuild project
2. **CodeBuild** orchestrates multi-account deployment and assessment
3. **Results** are consolidated in central S3 bucket
4. **Notifications** sent via SNS (if configured)

**Key Parameters:**
- `MultiAccountScan`: Set to `true` for multi-account scanning
- `MultiAccountListOverride`: Space-delimited list of specific accounts (optional)
- `EmailAddress`: Email for completion notifications (optional)
- `ConcurrentAccountScans`: Number of parallel scans (Three/Six/Twelve)

**Assessment Module Configuration (Environment Variables):**
- `DEPLOY_AIML_ASSESSMENT`: Deploy AI/ML assessment module (default: true)
- `DEPLOY_SECURITY_ASSESSMENT`: Deploy security assessment module (default: false)
- `DEPLOY_RESILIENCE_ASSESSMENT`: Deploy resilience assessment module (default: false)
- `DEPLOY_COST_ASSESSMENT`: Deploy cost assessment module (default: false)

## How It Works

### Single Account Mode (`MultiAccountScan=false`)
- Creates local `ReSCOAIMLMemberRole` 
- Runs assessment in the same account
- Uses local S3 bucket for results

### Multi-Account Mode (`MultiAccountScan=true`)
- Lists all active accounts in AWS Organizations
- Assumes `ReSCOAIMLMemberRole` in each target account
- Deploys selected assessment modules in each account with shared S3 bucket
- Executes Step Functions for each deployed module in each account
- Consolidates results by assessment type in central S3 bucket

### Assessment Execution Process

#### Automatic Trigger
- CodeBuild project starts automatically after central stack creation
- Lambda trigger function initiates the assessment workflow

#### Multi-Account Orchestration
1. **Account Discovery**: CodeBuild queries AWS Organizations for active accounts
2. **Role Assumption**: Assumes `ReSCOAIMLMemberRole` in each target account
3. **Module Deployment**: Conditionally deploys selected assessment modules:
   - AI/ML Assessment (Bedrock Lambda, SageMaker Lambda)
   - Security Assessment (EC2 Lambda, RDS Lambda, Lambda Lambda, VPC Lambda)
   - Resilience Assessment (Backup Lambda, HA Lambda, DR Lambda, FT Lambda)
   - Cost Assessment (Utilization Lambda, Optimization Lambda, Rightsizing Lambda, Waste Lambda)
4. **Assessment Execution**: Step Functions orchestrate parallel Lambda execution per module
5. **Results Collection**: Individual Lambda functions store results in local S3 buckets
6. **Consolidation**: CodeBuild collects and consolidates results from all accounts
7. **Reporting**: Generates multi-account, multi-module HTML and CSV reports
8. **Notification**: Sends completion notification via SNS (if configured)

## Permissions Required

### Central Account Role (`ReSCOCodeBuildRole`)
- Assume roles in member accounts
- List AWS Organizations accounts
- Deploy CloudFormation/SAM applications
- Execute Step Functions
- Write to S3 bucket

### Member Account Role (`ReSCOAIMLMemberRole`)
- Read-only access to AIML services (Bedrock, SageMaker)
- IAM read permissions for security assessment
- CloudTrail, GuardDuty, Lambda read permissions
- VPC and EC2 read permissions

## Monitoring and Results

- **S3 Bucket**: Central storage for all assessment results
- **CloudWatch Logs**: CodeBuild execution logs
- **SNS Notifications**: Email alerts on completion/failure
- **EventBridge Rules**: Automated workflow triggers

## Customization

### Adding New Accounts

#### Option A: AWS Console
1. Navigate to **CloudFormation** > **StackSets**
2. Select `resco-aiml-member-roles` StackSet
3. Click **Add stacks to StackSet**
4. Choose deployment targets:
   - **Deploy to accounts**: Enter specific account IDs
   - **Regions**: Select target regions
5. Review and click **Submit**

#### Option B: AWS CLI
```bash
aws cloudformation create-stack-instances \
  --stack-set-name resco-aiml-member-roles \
  --accounts 111111111111 222222222222 \
  --regions us-east-1
```

### Modifying Assessment Scope
Edit the member role permissions in `1-resco-member-roles.yaml` to add/remove service permissions.

### Concurrent Scanning
Adjust `ConcurrentAccountScans` parameter based on your organization size and cost considerations.

## Viewing Assessment Results

### Accessing Results

1. **Find the S3 Bucket Name**:
   - Navigate to **CloudFormation** > **Stacks** in the AWS Console
   - Select your `resco-aiml-multi-account` stack
   - Go to the **Outputs** tab
   - Copy the S3 bucket name from the `AssessmentBucketName` output

2. **Navigate to S3 Bucket**:
   - Go to **S3** in the AWS Console
   - Search for and open your assessment bucket

### Report Structure

#### Consolidated Reports
- **Location**: `consolidated-reports/` folder
- **Content**: Multi-account HTML report combining all account assessments
- **File Format**: `multi_account_report_YYYYMMDD_HHMMSS.html`

#### Individual Account Reports
- **Location**: Folders named with account IDs (e.g., `123456789012/`)
- **Content**: Account-specific CSV and HTML files organized by assessment type
- **Files Include**:
  - `aiml/` - AI/ML assessment results
    - `bedrock_assessment_*.csv` - Bedrock Lambda results
    - `sagemaker_assessment_*.csv` - SageMaker Lambda results
  - `security/` - Security assessment results
    - `ec2_security_*.csv` - EC2 Lambda results
    - `rds_security_*.csv` - RDS Lambda results
    - `lambda_security_*.csv` - Lambda Lambda results
    - `vpc_security_*.csv` - VPC Lambda results
  - `resilience/` - Resilience assessment results (per service Lambda)
  - `cost/` - Cost optimization assessment results (per service Lambda)
  - `consolidated_report_*.html` - Multi-module account report

### Sample Assessment Report

The consolidated report provides a comprehensive view of security findings across all accounts:

| Account ID | Finding | Finding Details | Resolution | Reference | Severity | Status |
|------------|---------|-----------------|------------|-----------|----------|--------|
| 3183XXXX3611 | Bedrock Model Invocation Logging Check | Model invocation logging is not enabled | Enable logging to S3 or CloudWatch for audit tracking | [Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) | Medium | Failed |
| 3183XXXX3611 | Bedrock Guardrails Check | No Guardrails configured | Configure content filters and safety measures | [Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html) | Medium | Failed |
| 3183XXXX3611 | Bedrock CloudTrail Logging Check | CloudTrail not configured for Bedrock API calls | Enable CloudTrail logging for audit compliance | [CloudTrail Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html) | High | Failed |
| 3183XXXX3611 | SageMaker Model Registry Issue | No model package groups found | Implement model versioning and lifecycle management | [MLOps Guide](https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html) | Medium | Failed |

### Understanding Results

- **Severity Levels**:
  - 🔴 **High**: Critical security issues requiring immediate attention
  - 🟡 **Medium**: Important security improvements recommended
  - 🔵 **Low**: Minor optimizations suggested
  - ✅ **N/A**: No issues found or not applicable

- **Status**:
  - **Failed**: Security issue identified
  - **Passed**: No issues found
  - **N/A**: Check not applicable to current configuration

## Troubleshooting

### Common Issues
1. **StackSet Deployment Failures**: Check service-linked roles and permissions
2. **Cross-Account Role Assumption**: Verify trust relationships and account IDs
3. **SAM Deployment Failures**: Check CodeBuild logs for specific errors
4. **Step Functions Execution**: Monitor state machine executions in each account

### Debugging
- Check CodeBuild project logs in CloudWatch
- Verify cross-account role trust policies
- Ensure S3 bucket permissions allow cross-account writes
- Monitor Step Functions executions for individual account assessments

## Contributing

We welcome community contributions! Please see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for guidelines.

## Security
- All roles follow least-privilege principle
- Cross-account trust limited to specific CodeBuild role
- S3 bucket enforces SSL-only access
- Assessment data encrypted in transit and at rest
- No persistent credentials stored in CodeBuild

See [Security issue notifications](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.