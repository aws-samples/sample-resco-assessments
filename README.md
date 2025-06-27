# ReSCO Assessments

## Overview
This monorepo contains a collection of tools and frameworks for performing ReSCO (Resilience, Security, and Cost Optimization) assessments across different types of workloads and infrastructures. It uses AWS serverless services to gather the data from the control plane and provide a list of assessments with the sevrity level and recommended actions.

ReSCO assessments help organizations evaluate and improve their:
- **Resilience**: System reliability, fault tolerance, and disaster recovery capabilities
- **Security**: Security posture, compliance, and risk management
- **Cost Optimization**: Resource utilization, cost efficiency, and optimization opportunities

## Projects

| Project | Description | Status |
|---------|------------|--------|
| [resco-aiml-assessment](./resco-aiml-assessment) | ReSCO assessment tools for AI/ML workloads | Active |

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

For single account deployment, proceed to Deployment Step #2 and choose Single Account Mode.

The multi-account deployment consists of:

1. **Central Security Account**: Runs the main assessment infrastructure
2. **Member Accounts**: Have cross-account roles that allow the central account to perform assessments

### Deployment Steps

#### Step 1: Deploy Member Roles (via StackSets)

Deploy `1-resco-member-roles.yaml` to all target accounts using CloudFormation StackSets.

#### Prerequisites
- AWS Organizations setup with management account access
- StackSets service-linked roles configured

#### Option A: AWS Console
1. Navigate to **CloudFormation** > **StackSets** in the AWS Console
2. Click **Create StackSet**
3. Choose **Template is ready** and **Upload a template file**
4. Upload `1-resco-member-roles.yaml`
5. Enter StackSet name: `resco-aiml-member-roles`
6. Set parameters:
   - `ReSCOAccountID`: Your central security account ID (e.g., 123456789012)
7. Configure StackSet options:
   - **Permissions**: Choose service-managed permissions
   - **Capabilities**: Check "I acknowledge that AWS CloudFormation might create IAM resources with custom names"
8. Set deployment targets:
   - **Deploy to**: Organization or Organizational units
   - **Regions**: Select your target region (e.g., us-east-1)
9. Review and click **Submit**

#### Option B: AWS CLI
```bash
# Create the StackSet
aws cloudformation create-stack-set \
  --stack-set-name resco-aiml-member-roles \
  --template-body file://1-resco-member-roles.yaml \
  --parameters ParameterKey=ReSCOAccountID,ParameterValue=123456789012 \
  --capabilities CAPABILITY_NAMED_IAM \
  --administration-role-arn arn:aws:iam::MANAGEMENT-ACCOUNT:role/service-role/AWSCloudFormationStackSetAdministrationRole \
  --execution-role-name AWSCloudFormationStackSetExecutionRole

# Deploy to target accounts
aws cloudformation create-stack-instances \
  --stack-set-name resco-aiml-member-roles \
  --deployment-targets OrganizationalUnitIds=ou-root-xxxxxxxxxx \
  --regions us-east-1 \
  --parameter-overrides ParameterKey=ReSCOAccountID,ParameterValue=123456789012
```

**Parameters:**
- `ReSCOAccountID`: Account ID where the central ReSCO infrastructure will run

### Step 2: Deploy Central Assessment Infrastructure

Deploy `2-resco-multi-account-assessment.yaml` in your central security account.

#### Option A: AWS Console
1. Navigate to **CloudFormation** > **Stacks** in the AWS Console
2. Click **Create stack** > **With new resources (standard)**
3. Choose **Template is ready** and **Upload a template file**
4. Upload `2-resco-multi-account-assessment.yaml`
5. Enter Stack name: `resco-aiml-multi-account`
6. Configure parameters:
   - `MultiAccountScan`: Select `true` for multi-account scanning
   - `MultiAccountListOverride`: Leave blank or enter space-delimited account IDs
   - `EmailAddress`: Enter your email for notifications (optional)
   - `ConcurrentAccountScans`: Choose Three, Six, or Twelve
7. Configure stack options (leave defaults)
8. Review and check:
   - "I acknowledge that AWS CloudFormation might create IAM resources with custom names"
9. Click **Submit**

#### Option B: AWS CLI
```bash
aws cloudformation create-stack \
  --stack-name resco-aiml-multi-account \
  --template-body file://2-resco-multi-account-assessment.yaml \
  --parameters \
    ParameterKey=MultiAccountScan,ParameterValue=true \
    ParameterKey=EmailAddress,ParameterValue=security-team@company.com \
    ParameterKey=ConcurrentAccountScans,ParameterValue=Three \
  --capabilities CAPABILITY_NAMED_IAM
```

**Key Parameters:**
- `MultiAccountScan`: Set to `true` for multi-account scanning
- `MultiAccountListOverride`: Space-delimited list of specific accounts (optional)
- `EmailAddress`: Email for completion notifications (optional)
- `ConcurrentAccountScans`: Number of parallel scans (Three/Six/Twelve)

## How It Works

### Single Account Mode (`MultiAccountScan=false`)
- Creates local `ReSCOAIMLMemberRole` 
- Runs assessment in the same account
- Uses local S3 bucket for results

### Multi-Account Mode (`MultiAccountScan=true`)
- Lists all active accounts in AWS Organizations
- Assumes `ReSCOAIMLMemberRole` in each target account
- Deploys SAM application in each account with shared S3 bucket
- Executes Step Functions in each account
- Consolidates results in central S3 bucket

### Assessment Process
1. CodeBuild project starts automatically after stack creation
2. For each target account:
   - Assumes cross-account role
   - Deploys ReSCO SAM application
   - Executes Step Functions state machine
   - Stores results in central S3 bucket
3. Sends completion notification (if configured)

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
- **Content**: Account-specific CSV and HTML files
- **Files Include**:
  - `bedrock_security_report_*.csv` - Bedrock assessment data
  - `sagemaker_security_report_*.csv` - SageMaker assessment data
  - `security_report_*.html` - Individual account HTML report

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

We welcome community contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security
- All roles follow least-privilege principle
- Cross-account trust limited to specific CodeBuild role
- S3 bucket enforces SSL-only access
- Assessment data encrypted in transit and at rest
- No persistent credentials stored in CodeBuild

See [Security issue notifications](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.