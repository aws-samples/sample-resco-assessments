# ReSCO AIML Multi-Account Deployment Guide

This guide explains how to deploy the ReSCO AIML assessment solution across multiple AWS accounts using CloudFormation StackSets.

## Architecture Overview

The multi-account deployment consists of:

1. **Central Security Account**: Runs the main assessment infrastructure
2. **Member Accounts**: Have cross-account roles that allow the central account to perform assessments

## Deployment Steps

### Step 1: Deploy Member Roles (via StackSets)

Deploy `1-resco-member-roles.yaml` to all target accounts using CloudFormation StackSets.

#### Prerequisites
- AWS Organizations setup with management account access
- StackSets service-linked roles configured

#### Deploy StackSet
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
Update the StackSet to include new organizational units or specific accounts:

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

## Security Considerations

- All roles follow least-privilege principle
- Cross-account trust limited to specific CodeBuild role
- S3 bucket enforces SSL-only access
- Assessment data encrypted in transit and at rest
- No persistent credentials stored in CodeBuild