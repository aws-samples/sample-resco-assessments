import boto3
import csv
import os
import logging
from datetime import datetime, timedelta, timezone
import time
from typing import Dict, List, Any, Optional
from io import StringIO
import asyncio
from botocore.config import Config
from botocore.exceptions import ClientError
import random
import json
#TO DO PYDANTIC SUPPORT
from schema import create_finding
# Configure boto3 with retries
boto3_config = Config(
    retries = dict(
        max_attempts = 10,  # Maximum number of retries
        mode = 'adaptive'  # Exponential backoff with adaptive mode
    )
)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

def get_permissions_cache(execution_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve and parse the permissions cache JSON file from S3
    
    Args:
        execution_id (str): Step Functions execution ID
    
    Returns:
        Optional[Dict[str, Any]]: Parsed permissions cache as dictionary, None if not found or error
    """
    try:
        s3_client = boto3.client('s3', config=boto3_config)
        date_string = get_current_utc_date()
        s3_key = f'permissions_cache_{execution_id}.json'
        s3_bucket = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')

        logger.info(f"Retrieving permissions cache from s3://{s3_bucket}/{s3_key}")
        
        try:
            # Get the JSON file from S3
            response = s3_client.get_object(
                Bucket=s3_bucket,
                Key=s3_key
            )
            
            # Read and parse the JSON content
            json_content = response['Body'].read().decode('utf-8')
            permissions_cache = json.loads(json_content)
            
            logger.info(f"Successfully retrieved permissions cache for execution {execution_id}")
            return permissions_cache
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                logger.warning(f"Permissions cache not found: s3://{s3_bucket}/{s3_key}")
            elif e.response['Error']['Code'] == 'NoSuchBucket':
                logger.error(f"Bucket not found: {s3_bucket}")
            else:
                logger.error(f"AWS error retrieving permissions cache: {str(e)}", exc_info=True)
            return None
            
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing permissions cache JSON: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error retrieving permissions cache: {str(e)}", exc_info=True)
        return None

def check_sagemaker_internet_access() -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances and domains have direct internet access
    """
    logger.debug("Starting check for SageMaker direct internet access")
    try:
        findings = {
            'csv_data': []
        }

        instances_with_direct_access = []
        domains_with_direct_access = []
        
        # Create SageMaker client
        sagemaker_client = boto3.client('sagemaker')
        
        # Check Notebook Instances
        try:
            paginator = sagemaker_client.get_paginator('list_notebook_instances')
            for page in paginator.paginate():
                for instance in page.get('NotebookInstances', []):
                    instance_name = instance.get('NotebookInstanceName')
                    if instance_name:
                        # Get detailed information about the notebook instance
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )
                        
                        # Check if direct internet access is enabled
                        if instance_details.get('DirectInternetAccess') == 'Enabled':
                            instances_with_direct_access.append({
                                'name': instance_name,
                                'subnet_id': instance_details.get('SubnetId', 'N/A'),
                                'vpc_id': instance_details.get('VpcId', 'N/A')
                            })
        except Exception as e:
            logger.error(f"Error checking notebook instances: {str(e)}")

        # Check SageMaker Domains
        try:
            paginator = sagemaker_client.get_paginator('list_domains')
            for page in paginator.paginate():
                for domain in page.get('Domains', []):
                    domain_id = domain.get('DomainId')
                    if domain_id:
                        # Get detailed information about the domain
                        domain_details = sagemaker_client.describe_domain(
                            DomainId=domain_id
                        )
                        
                        vpc_id = domain_details.get('DomainSettings', {}).get('SecurityGroupIds', ['N/A'])[0]
                        domain_name = domain_details.get('DomainName', 'N/A')
                        
                        # Check network access type
                        if domain_details.get('AppNetworkAccessType') != 'VpcOnly':
                            domains_with_direct_access.append({
                                'domain_id': domain_id,
                                'name': domain_name,
                                'vpc_id': vpc_id
                            })
        except Exception as e:
            logger.error(f"Error checking domains: {str(e)}")

        # Generate findings
        if instances_with_direct_access or domains_with_direct_access:
            findings['status'] = 'WARN'
            
            # Add findings for notebook instances
            for instance in instances_with_direct_access:
                findings['csv_data'].append(create_finding(
                    finding_name='Direct Internet Access Enabled',
                    finding_details=f"SageMaker notebook instance '{instance_name}' has direct internet access enabled",
                    resolution="Configure the notebook instance to use VPC connectivity and disable direct internet access",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                    severity='High',
                    status='Failed'
                    )
                )
            
            # Add findings for domains
            for domain in domains_with_direct_access:
                findings['csv_data'].append(create_finding(
                    finding_name='Non-VPC Only Network Access',
                    finding_details=f"SageMaker domain '{domain_id}' ({domain_name}) is not configured for VPC-only access",
                    resolution="Configure the SageMaker domain to use VPC-only network access type",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                    severity='High',
                    status='Failed'
                    )
                )
        else:
            findings['details'] = "No SageMaker resources found with direct internet access"
            findings['csv_data'].append(create_finding(
                finding_name= 'SageMaker Internet Access Check',
                finding_details= 'All SageMaker resources are properly configured to use VPC connectivity',
                resolution='',
                reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                severity='N/A',
                status='Passed'
            ))

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_internet_access: {str(e)}", exc_info=True)
        return {
            'check_name': 'SageMaker Internet Access Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def check_guardduty_enabled() -> Dict[str, Any]:
    """
    Check if GuardDuty is enabled in the account to monitor SageMaker security issues
    
    Returns:
        Dict[str, Any]: Finding details including status and recommendations
    """
    findings = {
        'check_name': 'GuardDuty Enablement Check',
        'status': 'PASS',
        'details': '',
        'csv_data': []
    }
    
    try:
        guardduty_client = boto3.client('guardduty')
        
        # Get list of detectors in the current region
        detectors = guardduty_client.list_detectors()
        
        if not detectors.get('DetectorIds'):
            findings['csv_data'].append(
                create_finding(
                    finding_name='GuardDuty Not Enabled',
                    finding_details='Amazon GuardDuty is not enabled in this account. GuardDuty can help detect security threats in SageMaker workloads.',
                    resolution='Enable Amazon GuardDuty to monitor for potential security threats in your SageMaker environment, including anomalous model access patterns and potential data exfiltration attempts.',
                    reference='https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html',
                    severity='High',
                    status='Failed'
                )
            )
        else:
            findings['csv_data'].append(
                create_finding(
                    finding_name='GuardDuty Enabled',
                    finding_details='Amazon GuardDuty is properly enabled and monitoring for security threats in SageMaker workloads.',
                    resolution='',
                    reference='https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html',
                    severity='N/A',
                    status='Passed'
                )
            )
            
            # Check if SageMaker protection is enabled
            detector_id = detectors['DetectorIds'][0]
            try:
                features = guardduty_client.get_detector(
                    DetectorId=detector_id
                ).get('Features', [])
                
                sagemaker_protection_enabled = False
                for feature in features:
                    if feature.get('Name') == 'RUNTIME_MONITORING' and feature.get('Status') == 'ENABLED':
                        sagemaker_protection_enabled = True
                        break
                
                if not sagemaker_protection_enabled:
                    findings['csv_data'].append(
                        create_finding(
                            finding_name='SageMaker Protection Not Enabled',
                            finding_details='SageMaker protection is not enabled in Amazon GuardDuty. This feature helps detect threats in SageMaker runtime operations.',
                            resolution='Enable SageMaker protection in GuardDuty to monitor for potential security threats in your SageMaker environment.',
                            reference='https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html',
                            severity='N/A',
                            status='N/A'
                        ))
            except ClientError as e:
                logger.warning(f"Could not check GuardDuty features: {str(e)}")
                
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        findings['csv_data'].append(
            create_finding(
                finding_name='GuardDuty Check Error',
                finding_details=f"Error checking GuardDuty status: {error_code} - {error_message}",
                resolution='Ensure proper IAM permissions to check GuardDuty status',
                reference='https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html',
                severity='High',
                status='Failed'
            )
            )
    except Exception as e:
        findings['csv_data'].append(
            create_finding(
                finding_name='GuardDuty Check Error',
                finding_details=f"Unexpected error checking GuardDuty status: {str(e)}",
                resolution='Investigate and resolve the unexpected error',
                reference='https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html',
                severity='High',
                status='Failed'    
            )
        )
        
    return findings

def check_sagemaker_iam_permissions(permission_cache) -> Dict[str, Any]:
    """
    Check SageMaker IAM permissions, SSO configuration, and stale access
    """
    logger.debug("Starting check for SageMaker IAM permissions")
    try:
        findings = {
            'csv_data': []
        }

        # Check for roles with SageMaker full access
        roles_with_full_access = []
        for role_name, permissions in permission_cache["role_permissions"].items():
            for policy in permissions['attached_policies']:
                if policy['name'] == 'AmazonSageMakerFullAccess':
                    roles_with_full_access.append(role_name)
                    break

        # Check for stale access
        stale_users = []
        iam_client = boto3.client('iam')
        two_months_ago = datetime.now(timezone.utc) - timedelta(days=60)

        # Check users' last access to SageMaker
        for user_name, permissions in permission_cache["user_permissions"].items():
            has_sagemaker_access = False
            for policy in permissions['attached_policies'] + permissions['inline_policies']:
                if has_sagemaker_permissions(policy['document']):
                    has_sagemaker_access = True
                    break
            
            if has_sagemaker_access:
                try:
                    response = iam_client.generate_service_last_accessed_details(
                        Arn=f"arn:aws:iam::{get_account_id()}:user/{user_name}"
                    )
                    job_id = response['JobId']
                    
                    # Wait for job completion
                    waiter_time = 0
                    while waiter_time < 10:
                        details = iam_client.get_service_last_accessed_details(JobId=job_id)
                        if details['JobStatus'] == 'COMPLETED':
                            for service in details['ServicesLastAccessed']:
                                if service['ServiceName'] == 'Amazon SageMaker':
                                    last_accessed = service.get('LastAuthenticated')
                                    if last_accessed and last_accessed < two_months_ago:
                                        stale_users.append({
                                            'name': user_name,
                                            'last_accessed': last_accessed
                                        })
                            break
                        time.sleep(1)
                        waiter_time += 1
                except Exception as e:
                    logger.error(f"Error checking last access for user {user_name}: {str(e)}")

        # Check SSO configuration
        domains_without_sso = []
        try:
            sagemaker_client = boto3.client('sagemaker')
            paginator = sagemaker_client.get_paginator('list_domains')
            
            for page in paginator.paginate():
                for domain in page['Domains']:
                    domain_id = domain['DomainId']
                    try:
                        domain_details = sagemaker_client.describe_domain(
                            DomainId=domain_id
                        )
                        
                        # Check authentication mode
                        auth_mode = domain_details.get('AuthMode', '')
                        if auth_mode != 'SSO':
                            domains_without_sso.append({
                                'domain_id': domain_id,
                                'domain_name': domain_details.get('DomainName', 'N/A'),
                                'auth_mode': auth_mode
                            })
                            
                        # Check if SSO is properly configured with Identity Center
                        if auth_mode == 'SSO':
                            try:
                                # Check Identity Center configuration
                                sso_client = boto3.client('sso-admin')
                                identity_store_id = domain_details.get('IdentityStoreId')
                                
                                if not identity_store_id:
                                    domains_without_sso.append({
                                        'domain_id': domain_id,
                                        'domain_name': domain_details.get('DomainName', 'N/A'),
                                        'auth_mode': 'SSO (Incomplete Configuration)'
                                    })
                            except Exception as sso_error:
                                logger.error(f"Error checking SSO configuration for domain {domain_id}: {str(sso_error)}")
                                
                    except Exception as domain_error:
                        logger.error(f"Error checking domain {domain_id}: {str(domain_error)}")
                        
        except Exception as e:
            logger.error(f"Error checking SSO configuration: {str(e)}")


        # Generate findings
        if roles_with_full_access or stale_users:
            
            # Findings for full access roles
            if roles_with_full_access:
                for role_name in roles_with_full_access:
                    findings['csv_data'].append(create_finding(
                        finding_name='SageMaker Full Access Policy Used',
                        finding_details=f"Role '{role_name}' has AmazonSageMakerFullAccess policy attached",
                        resolution="Replace AmazonSageMakerFullAccess with more restrictive custom policies that follow the principle of least privilege",
                        reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                        severity='High',
                        status='Failed'
                    )
                )

            # Findings for stale users
            if stale_users:
                for user in stale_users:
                    findings['csv_data'].append(create_finding(
                        finding_name='Stale SageMaker Access',
                        finding_details=f"User '{user["user_name"]}' hasn't accessed SageMaker since {last_accessed.strftime('%Y-%m-%d')}",
                        resolution="Review and remove SageMaker access for inactive users",
                        reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                        severity='Medium',
                        status='Failed'
                    )
                )

            # Findings for SSO
            if domains_without_sso:
                for domain in domains_without_sso:
                    findings['csv_data'].append(
                        create_finding(
                            finding_name="SSO Not Properly Configured",
                            finding_details=(
                                f"SageMaker domain '{domain['domain_id']}' ({domain['domain_name']}) "
                                f"is using authentication mode: {domain['auth_mode']}"
                            ),
                            resolution=(
                                "Enable and properly configure AWS IAM Identity Center (successor to AWS SSO) "
                                "for centralized access management. Ensure Identity Store ID is configured."
                            ),
                            reference="https://aws.amazon.com/blogs/machine-learning/team-and-user-management-with-amazon-sagemaker-and-aws-sso/",
                            severity='Medium',
                            status='Failed'
                        )
                    )
        else:
            findings['csv_data'].append(
                create_finding(
                    finding_name='SageMaker IAM Permissions Check',
                    finding_details='No issues found with IAM permissions, SSO is enabled, and no stale access detected',
                    resolution='',
                    reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                    severity='N/A',
                    status='Passed'
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_iam_permissions: {str(e)}", exc_info=True)
        return {
            'check_name': 'SageMaker IAM Permissions Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def has_sagemaker_permissions(policy_doc: Dict) -> bool:
    """
    Check if a policy document contains SageMaker permissions
    """
    try:
        statements = policy_doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for statement in statements:
            effect = statement.get('Effect', '')
            if effect.upper() != 'ALLOW':
                continue

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if 'sagemaker' in action.lower():
                    return True
        return False
    except Exception as e:
        logger.error(f"Error parsing policy document: {str(e)}")
        return False

def get_account_id() -> str:
    """
    Get current AWS account ID
    """
    try:
        sts_client = boto3.client('sts')
        return sts_client.get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Error getting account ID: {str(e)}")
        raise

def check_sagemaker_data_protection() -> Dict[str, Any]:
    """
    Check SageMaker data protection configurations including encryption at rest and in transit
    """
    logger.debug("Starting check for SageMaker data protection")
    try:
        findings = {
            'csv_data': []
        }

        sagemaker_client = boto3.client('sagemaker')
        kms_client = boto3.client('kms')
        
        # Track resources with encryption issues
        resources_with_aws_managed_keys = []
        resources_without_encryption = []
        resources_without_vpc_encryption = []

        # Check Notebook Instances
        try:
            paginator = sagemaker_client.get_paginator('list_notebook_instances')
            for page in paginator.paginate():
                for instance in page.get('NotebookInstances', []):
                    instance_name = instance.get('NotebookInstanceName')
                    if instance_name:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )
                        
                        # Check KMS key usage
                        kms_key_id = instance_details.get('KmsKeyId')
                        if not kms_key_id:
                            resources_without_encryption.append({
                                'type': 'Notebook Instance',
                                'name': instance_name,
                                'issue': 'No KMS key configured'
                            })
                        elif 'aws/sagemaker' in kms_key_id:
                            resources_with_aws_managed_keys.append({
                                'type': 'Notebook Instance',
                                'name': instance_name,
                                'key_id': kms_key_id
                            })
        except Exception as e:
            logger.error(f"Error checking notebook instances encryption: {str(e)}")

        # Check SageMaker Domains
        try:
            paginator = sagemaker_client.get_paginator('list_domains')
            for page in paginator.paginate():
                for domain in page.get('Domains', []):
                    domain_id = domain.get('DomainId')
                    if domain_id:
                        domain_details = sagemaker_client.describe_domain(
                            DomainId=domain_id
                        )
                        
                        # Check KMS key usage for domain
                        kms_key_id = domain_details.get('KmsKeyId')
                        if not kms_key_id:
                            resources_without_encryption.append({
                                'type': 'Domain',
                                'name': domain_details.get('DomainName', domain_id),
                                'issue': 'No KMS key configured'
                            })
                        elif 'aws/sagemaker' in kms_key_id:
                            resources_with_aws_managed_keys.append({
                                'type': 'Domain',
                                'name': domain_details.get('DomainName', domain_id),
                                'key_id': kms_key_id
                            })

                        # Check VPC encryption settings
                        vpc_settings = domain_details.get('DefaultUserSettings', {}).get('SecurityGroups', [])
                        if not vpc_settings:
                            resources_without_vpc_encryption.append({
                                'type': 'Domain',
                                'name': domain_details.get('DomainName', domain_id),
                                'issue': 'No VPC encryption configuration'
                            })
        except Exception as e:
            logger.error(f"Error checking domain encryption: {str(e)}")

        # Check Training Jobs encryption
        try:
            paginator = sagemaker_client.get_paginator('list_training_jobs')
            for page in paginator.paginate():
                for job in page.get('TrainingJobSummaries', []):
                    job_name = job.get('TrainingJobName')
                    if job_name:
                        job_details = sagemaker_client.describe_training_job(
                            TrainingJobName=job_name
                        )
                        
                        # Check output encryption
                        output_config = job_details.get('OutputDataConfig', {})
                        kms_key_id = output_config.get('KmsKeyId')
                        
                        if not kms_key_id:
                            resources_without_encryption.append({
                                'type': 'Training Job',
                                'name': job_name,
                                'issue': 'No output encryption configured'
                            })
                        elif 'aws/sagemaker' in kms_key_id:
                            resources_with_aws_managed_keys.append({
                                'type': 'Training Job',
                                'name': job_name,
                                'key_id': kms_key_id
                            })

                        # Check inter-node encryption for distributed training
                        if job_details.get('EnableInterContainerTrafficEncryption') is not True:
                            resources_without_vpc_encryption.append({
                                'type': 'Training Job',
                                'name': job_name,
                                'issue': 'Inter-container traffic encryption not enabled'
                            })
        except Exception as e:
            logger.error(f"Error checking training jobs encryption: {str(e)}")

        # Generate findings
        if resources_without_encryption or resources_with_aws_managed_keys or resources_without_vpc_encryption:
            
            # Resources without encryption
            for resource in resources_without_encryption:
                findings['csv_data'].append(
                    create_finding(
                        finding_name='Missing Encryption Configuration',
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Configure encryption using AWS KMS customer managed keys for enhanced security",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity='High',
                        status='Failed'
                    )
                )

            # Resources using AWS managed keys
            for resource in resources_with_aws_managed_keys:
                findings['csv_data'].append(
                    create_finding(
                        finding_name='AWS Managed Key Usage',
                        finding_details=f"{resource['type']} '{resource['name']}' uses AWS managed key {resource['key_id']}",
                        resolution="Consider using customer managed keys for better control over encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity='Low',
                        status='Failed'
                    )
                )

            # Resources without VPC encryption
            for resource in resources_without_vpc_encryption:
                findings['csv_data'].append(
                    create_finding(
                        finding_name='Missing VPC Encryption',
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Enable encryption for inter-container traffic and VPC communication",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-in-transit.html",
                        severity='Medium',
                        status='Failed'
                    )
                    )

        else:
            findings['csv_data'].append(
                create_finding(
                    finding_name='Data Protection Check',
                    finding_details='All resources use appropriate encryption configurations',
                    resolution='',
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity='N/A',
                    status='Passed'
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_data_protection: {str(e)}", exc_info=True)
        return {
            'csv_data': []
        }

def check_sagemaker_mlops_utilization(permission_cache) -> Dict[str, Any]:
    """
    Check if SageMaker MLOps features (Model Registry, Feature Store, and Pipelines) 
    are being utilized properly
    """
    logger.debug("Starting check for SageMaker MLOps features utilization")
    try:
        findings = {
            'csv_data': []
        }

        sagemaker_client = boto3.client('sagemaker', config=boto3_config)
        issues_found = []
        
        # Check Model Registry Usage
        try:
            model_packages = []
            paginator = sagemaker_client.get_paginator('list_model_package_groups')
            for page in paginator.paginate():
                model_packages.extend(page.get('ModelPackageGroupSummaryList', []))
            
            if not model_packages:
                issues_found.append({
                    'component': 'Model Registry',
                    'issue': 'No model package groups found',
                    'impact': 'Model versioning and governance may not be properly tracked',
                    'severity': 'Medium',
                    'status': "Failed"
                })
            else:
                # Check if models are being versioned
                for group in model_packages:
                    group_name = group.get('ModelPackageGroupName')
                    if group_name:
                        response = sagemaker_client.list_model_packages(
                            ModelPackageGroupName=group_name
                        )
                        if len(response.get('ModelPackageSummaryList', [])) <= 1:
                            issues_found.append({
                                'component': 'Model Registry',
                                'issue': f"Model group '{group_name}' has minimal versioning",
                                'impact': 'Limited model version tracking detected',
                                'severity': 'Low',
                                'status': "Failed"
                            })
        except Exception as e:
            logger.error(f"Error checking Model Registry: {str(e)}")
            issues_found.append({
                'component': 'Model Registry',
                'issue': f"Error checking configuration: {str(e)}",
                'impact': 'Unable to verify model versioning',
                'severity': 'High',
                "status": "Failed"
            })

        # Check Feature Store Usage
        try:
            feature_groups = []
            paginator = sagemaker_client.get_paginator('list_feature_groups')
            for page in paginator.paginate():
                feature_groups.extend(page.get('FeatureGroupSummaries', []))
            
            if not feature_groups:
                issues_found.append({
                    'component': 'Feature Store',
                    'issue': 'No feature groups found',
                    'impact': 'Feature reuse and sharing may be limited',
                    'severity': 'N/A',
                    'status': 'N/A'
                })
            else:
                # Check feature group status and configuration
                for group in feature_groups:
                    if group.get('FeatureGroupStatus') != 'Created':
                        issues_found.append({
                            'component': 'Feature Store',
                            'issue': f"Feature group '{group.get('FeatureGroupName')}' is not in Created state",
                            'impact': 'Feature group may not be properly configured',
                            'severity': 'Medium',
                            'status': 'Failed'
                        })
        except Exception as e:
            logger.error(f"Error checking Feature Store: {str(e)}")
            issues_found.append({
                'component': 'Feature Store',
                'issue': f"Error checking configuration: {str(e)}",
                'impact': 'Unable to verify feature management',
                'severity': 'High',
                'status': 'Failed'
            })

        # Check Pipeline Usage
        try:
            pipelines = []
            paginator = sagemaker_client.get_paginator('list_pipelines')
            for page in paginator.paginate():
                pipelines.extend(page.get('PipelineSummaries', []))
            
            if not pipelines:
                issues_found.append({
                    'component': 'Pipelines',
                    'issue': 'No ML pipelines found',
                    'impact': 'Automated ML workflows may not be implemented',
                    'severity': 'N/A',
                    'status': 'N/A'
                })
            else:
                # Check pipeline status and execution history
                for pipeline in pipelines:
                    pipeline_name = pipeline.get('PipelineName')
                    if pipeline_name:
                        executions = sagemaker_client.list_pipeline_executions(
                            PipelineName=pipeline_name,
                            MaxResults=1
                        )
                        if not executions.get('PipelineExecutionSummaries'):
                            issues_found.append({
                                'component': 'Pipelines',
                                'issue': f"Pipeline '{pipeline_name}' has no execution history",
                                'impact': 'Pipeline may be defined but not actively used',
                                'severity': 'Low',
                                'status': 'Failed'
                            })
        except Exception as e:
            logger.error(f"Error checking Pipelines: {str(e)}")
            issues_found.append({
                'component': 'Pipelines',
                'issue': f"Error checking configuration: {str(e)}",
                'impact': 'Unable to verify pipeline automation',
                'severity': 'High',
                'status': 'Failed'
            })

        # Generate findings based on issues found
        if issues_found:
            findings['status'] = 'WARN'
            findings['details'] = f"Found {len(issues_found)} issues with SageMaker MLOps features"
            
            for issue in issues_found:
                findings['csv_data'].append(
                    create_finding(
                        finding_name=f"SageMaker {issue['component']} Issue",
                        finding_details=issue['issue'],
                        resolution=get_resolution_for_component(issue['component']),
                        reference='https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html',
                        severity=issue['severity'],
                        status=issue['status']
                    )
                )
        else:
            findings['details'] = "All SageMaker MLOps features are properly utilized"
            findings['csv_data'].append(
                create_finding(
                    finding_name='SageMaker MLOps Features Check',
                    finding_details='All SageMaker MLOps features are properly utilized',
                    resolution='',
                    reference='https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html',
                    severity='N/A',
                    status='Passed'
                ))

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_mlops_utilization: {str(e)}", exc_info=True)
        return {
            'check_name': 'SageMaker MLOps Features Utilization Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def get_resolution_for_component(component: str) -> str:
    """
    Helper function to provide specific resolutions based on the component
    """
    resolutions = {
        'Model Registry': (
            "Implement model versioning using SageMaker Model Registry to track model lineage, "
            "approve model versions, and manage model deployment"
        ),
        'Feature Store': (
            "Utilize SageMaker Feature Store to create, share, and manage features "
            "for machine learning development and production"
        ),
        'Pipelines': (
            "Implement SageMaker Pipelines to automate and manage ML workflows, "
            "including data preparation, training, and model deployment"
        )
    }
    return resolutions.get(component, "Review and implement appropriate SageMaker MLOps features")

def check_sagemaker_clarify_usage(permission_cache) -> Dict[str, Any]:
    """
    Check if SageMaker Clarify is being used for bias detection and model explainability
    """
    logger.debug("Starting check for SageMaker Clarify usage")
    try:
        findings = {
            'csv_data': []
        }

        sagemaker_client = boto3.client('sagemaker', config=boto3_config)
        issues_found = []

        try:
            # Check Processing Jobs for Clarify
            paginator = sagemaker_client.get_paginator('list_processing_jobs')
            clarify_jobs_found = False
            
            for page in paginator.paginate():
                for job in page['ProcessingJobSummaries']:
                    job_name = job['ProcessingJobName']
                    job_details = sagemaker_client.describe_processing_job(
                        ProcessingJobName=job_name
                    )
                    
                    # Check if it's a Clarify job
                    if 'clarify' in job_details.get('AppSpecification', {}).get('ImageUri', '').lower():
                        clarify_jobs_found = True
                        # Check job status
                        if job_details['ProcessingJobStatus'] == 'Failed':
                            issues_found.append({
                                'issue_type': 'Failed Clarify Job',
                                'details': f"Clarify job {job_name} failed",
                                'severity': 'High',
                                'status': 'Failed'
                            })

            if not clarify_jobs_found:
                issues_found.append({
                    'issue_type': 'No Clarify Usage',
                    'details': 'No SageMaker Clarify jobs found',
                    'severity': 'N/A',
                    'status': 'N/A'
                })

        except Exception as e:
            logger.error(f"Error checking Clarify jobs: {str(e)}")
            issues_found.append({
                'issue_type': 'Clarify Check Error',
                'details': f"Error checking Clarify configuration: {str(e)}",
                'severity': 'High',
                'status': 'Failed'
            })

        if issues_found:
            
            for issue in issues_found:
                findings['csv_data'].append(
                    create_finding(
                        finding_name=f"SageMaker Clarify {issue['issue_type']}",
                        finding_details=issue['details'],
                        resolution="Implement SageMaker Clarify for model explainability and bias detection",
                        reference='https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html',
                        severity=issue['severity'],
                        status=issue['status']
                    )
                )
        else:
            findings['details'] = "SageMaker Clarify is properly utilized"
            findings['csv_data'].append(
                create_finding(
                    finding_name='SageMaker Clarify Usage Check',
                    finding_details='SageMaker Clarify is properly utilized',
                    resolution='',
                    reference='https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html',
                    severity='N/A',
                    status='Passed'
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_clarify_usage: {str(e)}", exc_info=True)
        return {
            'check_name': 'SageMaker Clarify Usage Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def check_sagemaker_model_monitor_usage(permission_cache) -> Dict[str, Any]:
    """
    Check if SageMaker Model Monitor is configured and actively monitoring models
    """
    logger.debug("Starting check for SageMaker Model Monitor usage")
    try:
        findings = {
            'csv_data': []
        }

        sagemaker_client = boto3.client('sagemaker', config=boto3_config)
        issues_found = []

        try:
            # Check monitoring schedules
            paginator = sagemaker_client.get_paginator('list_monitoring_schedules')
            monitoring_found = False
            
            for page in paginator.paginate():
                for schedule in page['MonitoringScheduleSummaries']:
                    monitoring_found = True
                    schedule_name = schedule['MonitoringScheduleName']
                    schedule_details = sagemaker_client.describe_monitoring_schedule(
                        MonitoringScheduleName=schedule_name
                    )
                    
                    # Check schedule status
                    if schedule_details['MonitoringScheduleStatus'] != 'Scheduled':
                        issues_found.append({
                            'issue_type': 'Inactive Monitor',
                            'details': f"Monitoring schedule {schedule_name} is not active",
                            'severity': 'Medium',
                            'status': 'Failed'
                        })

            if not monitoring_found:
                issues_found.append({
                    'issue_type': 'No Model Monitoring',
                    'details': 'No Model Monitor schedules found',
                    'severity': 'N/A',
                    'status': 'N/A'
                })

        except Exception as e:
            logger.error(f"Error checking Model Monitor: {str(e)}")
            issues_found.append({
                'issue_type': 'Monitor Check Error',
                'details': f"Error checking Model Monitor configuration: {str(e)}",
                'severity': 'High',
                'status': 'Failed'
            })

        if issues_found:
            
            for issue in issues_found:
                findings['csv_data'].append(
                    create_finding(
                        finding_name=f"SageMaker Model Monitor {issue['issue_type']}",
                        finding_details=issue['details'],
                        resolution="Configure comprehensive model monitoring schedules",
                        reference='https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html',
                        severity=issue['severity'],
                        status=issue['status']
                    )
                )
        else:
            findings['csv_data'].append(
                create_finding(
                    finding_name='SageMaker Model Monitor Usage Check',
                    finding_details='SageMaker Model Monitor is actively tracking model performance',
                    resolution='',
                    reference='https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html',
                    severity='N/A',
                    status='Passed'
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_model_monitor_usage: {str(e)}", exc_info=True)
        return {
            'check_name': 'SageMaker Model Monitor Usage Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def check_model_registry_usage(permission_cache) -> Dict[str, Any]:
    """
    Check if Amazon Model Registry is being used effectively for model management
    """
    logger.debug("Starting check for Model Registry usage")
    try:
        findings = {
            'csv_data': []
        }

        sagemaker_client = boto3.client('sagemaker', config=boto3_config)
        issues_found = []

        try:
            # Check Model Package Groups
            paginator = sagemaker_client.get_paginator('list_model_package_groups')
            registry_used = False
            
            for page in paginator.paginate():
                for group in page['ModelPackageGroupSummaryList']:
                    registry_used = True
                    group_name = group['ModelPackageGroupName']
                    
                    # Check model versions in the group
                    try:
                        models = sagemaker_client.list_model_packages(
                            ModelPackageGroupName=group_name
                        )
                        
                        if not models.get('ModelPackageSummaryList'):
                            issues_found.append({
                                'issue_type': 'Empty Model Group',
                                'details': f"Model group {group_name} has no registered models",
                                'severity': 'Low',
                                'status': 'Failed'
                            })
                        else:
                            # Check model approval status
                            approved_models = [m for m in models['ModelPackageSummaryList'] 
                                            if m.get('ModelApprovalStatus') == 'Approved']
                            if not approved_models:
                                issues_found.append({
                                    'issue_type': 'No Approved Models',
                                    'details': f"Model group {group_name} has no approved models",
                                    'severity': 'N/A',
                                    'status': 'N/A'
                                })
                    
                    except Exception as e:
                        logger.error(f"Error checking models in group {group_name}: {str(e)}")
                        issues_found.append({
                            'issue_type': 'Model Check Error',
                            'details': f"Error checking models in group {group_name}",
                            'severity': 'Medium',
                            'status': 'Failed'
                        })

            if not registry_used:
                issues_found.append({
                    'issue_type': 'Registry Not Used',
                    'details': 'Model Registry is not being utilized',
                    'severity': 'N/A',
                    'status': 'N/A'
                })

        except Exception as e:
            logger.error(f"Error checking Model Registry: {str(e)}")
            issues_found.append({
                'issue_type': 'Registry Check Error',
                'details': f"Error checking Model Registry configuration: {str(e)}",
                'severity': 'High',
                'status': 'Failed'
            })

        if issues_found:
            
            for issue in issues_found:
                findings['csv_data'].append(
                    create_finding(
                        finding_name=f"Model Registry {issue['issue_type']}",
                        finding_details=issue['details'],
                        resolution="Implement proper model versioning and approval workflows",
                        reference='https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html',
                        severity=issue['severity'],
                        status=issue['status']
                    )
                )
        else:
            findings['csv_data'].append(
                create_finding(
                    finding_name='Model Registry Usage Check',
                    finding_details='Model Registry is being used effectively',
                    resolution='',
                    reference='https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html',
                    severity='N/A',
                    status='Passed'
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_registry_usage: {str(e)}", exc_info=True)
        return {
            'check_name': 'Model Registry Usage Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def get_role_usage(role_name: str) -> str:
    """
    Check where a specific IAM role is being used
    """
    logger.debug(f"Checking usage for role: {role_name}")
    usage_list = []
    
    try:
        # Check Lambda functions
        lambda_client = boto3.client('lambda')
        lambda_functions = lambda_client.list_functions()
        for function in lambda_functions['Functions']:
            if role_name in function['Role']:
                usage_list.append(f"Lambda: {function['FunctionName']}")
                logger.debug(f"Found role usage in Lambda: {function['FunctionName']}")
    except Exception as e:
        logger.error(f"Error checking Lambda usage: {str(e)}")
    
    try:
        # Check ECS tasks
        ecs_client = boto3.client('ecs')
        clusters = ecs_client.list_clusters()['clusterArns']
        for cluster in clusters:
            tasks = ecs_client.list_tasks(cluster=cluster)['taskArns']
            if tasks:
                task_details = ecs_client.describe_tasks(cluster=cluster, tasks=tasks)
                for task in task_details['tasks']:
                    if role_name in task.get('taskRoleArn', ''):
                        usage_list.append(f"ECS Task: {task['taskArn']}")
                        logger.debug(f"Found role usage in ECS task: {task['taskArn']}")
    except Exception as e:
        logger.error(f"Error checking ECS usage: {str(e)}")
    
    result = '; '.join(usage_list) if usage_list else 'No active usage found'
    logger.debug(f"Role usage result: {result}")
    return result

def handle_aws_throttling(func, *args, **kwargs):
    """
    Handle AWS API throttling with exponential backoff
    """
    max_retries = 5
    base_delay = 1  # Start with 1 second delay
    
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] == 'Throttling':
                if attempt == max_retries - 1:
                    raise  # Re-raise if we're out of retries
                delay = (2 ** attempt) * base_delay + (random.random() * 0.1)
                logger.warning(f"Request throttled. Retrying in {delay:.2f} seconds...")
                time.sleep(delay)
            else:
                raise

def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate CSV report from all security check findings
    """
    logger.debug("Generating CSV report")
    csv_buffer = StringIO()
    fieldnames = ['Finding', 'Finding_Details', 'Resolution', 'Reference', 'Severity', 'Status']
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    
    writer.writeheader()
    for finding in findings:
        if finding['csv_data']:
            for row in finding['csv_data']:
                writer.writerow(row)
    
    return csv_buffer.getvalue()
def get_current_utc_date():
    return datetime.utcnow().strftime("%Y/%m/%d")

def write_to_s3(execution_id, csv_content: str, bucket_name: str) -> Dict[str, str]:
    """
    Write CSV reports to S3 bucket
    """
    logger.debug(f"Writing reports to S3 bucket: {bucket_name}")
    try:
        s3_client = boto3.client('s3', config=boto3_config)
        
        # Upload CSV file
        date_string = get_current_utc_date()
        csv_file_name = f'sagemaker_security_report_{execution_id}.csv'
        s3_client.put_object(
            Bucket=bucket_name,
            Key=csv_file_name,
            Body=csv_content,
            ContentType='text/csv'
        )
        
        return {
            'csv_url': f"https://{bucket_name}.s3.amazonaws.com/{csv_file_name}",
        }
    except Exception as e:
        logger.error(f"Error writing to S3: {str(e)}", exc_info=True)
        raise

def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Starting Bedrock security assessment")
    all_findings = []
    
    try:
        # Initialize permission cache
        logger.info("Initializing IAM permission cache")
        execution_id = event["Execution"]["Name"]
        permission_cache = get_permissions_cache(execution_id)
                
        logger.info("Running SageMaker internet access check")
        sagemaker_internet_access_findings = check_sagemaker_internet_access()
        all_findings.append(sagemaker_internet_access_findings)

        logger.info("Running SageMaker IAM permissions check")
        sagemaker_iam_findings = check_sagemaker_iam_permissions(permission_cache)
        all_findings.append(sagemaker_iam_findings)

        logger.info("Running SageMaker data protection check")
        sagemaker_data_protection_findings = check_sagemaker_data_protection()
        all_findings.append(sagemaker_data_protection_findings)

        logger.info("Running GuardDuty SageMaker monitoring check")
        guardduty_findings = check_guardduty_enabled()
        all_findings.append(guardduty_findings)

        logger.info("Running SageMaker MLOps features utilization check")
        mlops_findings = check_sagemaker_mlops_utilization(permission_cache)
        all_findings.append(mlops_findings)

        logger.info("Running SageMaker Clarify usage check")
        clarify_findings = check_sagemaker_clarify_usage(permission_cache)
        all_findings.append(clarify_findings)

        logger.info("Running SageMaker Model Monitor usage check")
        monitor_findings = check_sagemaker_model_monitor_usage(permission_cache)
        all_findings.append(monitor_findings)

        logger.info("Running Model Registry usage check")
        registry_findings = check_model_registry_usage(permission_cache)
        all_findings.append(registry_findings)

        # Generate and upload report
        logger.info("Generating reports")
        csv_content = generate_csv_report(all_findings)
        
        bucket_name = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')
        if not bucket_name:
            raise ValueError("AIML_ASSESSMENT_BUCKET_NAME environment variable is not set")
        
        logger.info("Writing reports to S3")
        s3_url = write_to_s3(execution_id, csv_content, bucket_name)
        
        return {
            'statusCode': 200,
            'body': {
                'message': 'Security checks completed successfully',
                'findings': all_findings,
                'report_url': s3_url
            }
        }
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': f'Error during security checks: {str(e)}'
        }
