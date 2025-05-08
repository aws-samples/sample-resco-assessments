# ReSCO AI/ML Assessment Framework

## Overview
ReSCO AI/ML Assessment Framework is a serverless solution designed to perform comprehensive Resilience, Security, and Cost Optimization (ReSCO) assessments for AI/ML workloads on AWS. The initial release focuses on security assessments for Amazon Bedrock and Amazon SageMaker workloads.

## Architecture
![Architecture Diagram](images/AI_MLReSCOAssessment.jpeg)

The solution leverages AWS Serverless services:

- **AWS Step Functions**: Orchestrates the assessment workflow
- **AWS Lambda**: Executes individual assessment checks
- **Amazon S3**: Stores assessment reports

## Features

### Current Features
Security Assessments for:
- **Amazon Bedrock**
  - Network Isolation
  - Data Protection
  - Identity and Access Management
- **Amazon SageMaker**
  - Compute and network isolation
  - Authentication and authorization
  - Data protection
  - Governance and Auditability

### Roadmap
- **Resilience Assessments**
- **Cost Optimization Assessments**

## Prerequisites
- AWS Account with appropriate permissions
- Python 3.12+ - [Install Python](https://www.python.org/downloads/)
- SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community)

## Installation

1. Clone the repository
```bash
git clone https://github.com/your-username/resco-assessments.git
cd resco-assessments/resco-aiml-assessment
```

2. Build the SAM application
```bash
sam build
```

3. Deploy the stack
```bash
sam deploy --guided
```

During the guided deployment, you'll be prompted for the following parameters:
- Stack Name (e.g., resco-aiml-assessment)
- AWS Region
- Confirm changes before deploy
- Allow SAM CLI IAM role creation
- S3 bucket name for assessment reports


## Usage

### Running Assessments
1. Navigate to Step Functions console
2. Select the state machine starting with name AIMLAssessmentStateMachine
3. Click "Start Execution"
4. Navigate to Amazon S3 bucket starting with name resco-aiml-assessment. This bucket will contain the reaso assessment results.


## Project Structure
```
resco-aiml-assessment/
├── template.yaml               # SAM template
├── functions/
│   ├── security/ 
│       ├── bedrock/              # Bedrock assessment functions
│       ├── sagemaker/            # SageMaker assessment functions
└── statemachine/                 # Contains the state machine definition
```

### Local Testing

Making report file: sam local invoke GenerateConsolidatedReportFunction --env-vars envvars.json -e testfile.json | 2>&1

## Step Functions Workflow
![Step Functions Workflow](images/StepFunctionsFlow.png)

## References
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [Amazon SageMaker Security](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
