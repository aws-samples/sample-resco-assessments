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

def check_marketplace_subscription_access(permission_cache) -> Dict[str, Any]:
    logger.debug("Starting check for overly permissive Marketplace subscription access")
    try:
        findings = {
            'check_name': 'Marketplace Subscription Access Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        overly_permissive_identities = []
        
        def check_policy_for_subscription_access(policy_doc: Any) -> bool:
            try:
                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)

                if not policy_doc:
                    return False

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

                    resources = statement.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]

                    if 'aws-marketplace:Subscribe' in actions:
                        if '*' in resources:
                            return True

                return False
            except Exception as e:
                logger.error(f"Error parsing policy document for subscription access: {str(e)}")
                return False

        # Check roles
        for role_name, permissions in permission_cache["role_permissions"].items():
            for policy in permissions['attached_policies'] + permissions['inline_policies']:
                if check_policy_for_subscription_access(policy['document']):
                    overly_permissive_identities.append({
                        'name': role_name,
                        'type': 'role',
                        'policy': policy['name']
                    })
                    break

        # Check users
        for user_name, permissions in permission_cache["user_permissions"].items():
            for policy in permissions['attached_policies'] + permissions['inline_policies']:
                if check_policy_for_subscription_access(policy['document']):
                    overly_permissive_identities.append({
                        'name': user_name,
                        'type': 'user',
                        'policy': policy['name']
                    })
                    break

        if overly_permissive_identities:
            findings['status'] = 'WARN'
            findings['details'] = f"Found {len(overly_permissive_identities)} identities with overly permissive marketplace subscription access"
            
            for identity in overly_permissive_identities:
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Marketplace Subscription Access Check",
                        finding_details=f"{identity['type'].capitalize()} '{identity['name']}' has overly permissive marketplace subscription access through policy '{identity['policy']}'",
                        resolution="Ensure that users have access to only the models that you want user to be able to subscribe to based on your organizational policies. For example, you may want users to have access to only text based models and not image and video generation model. This can also help to keep cost in check.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html#security-iam-awsmanpol-bedrock-marketplace",
                        severity='Medium',
                        status='Failed'
                    )
            )
        else:
            findings['details'] = "No identities found with overly permissive marketplace subscription access"
            findings['csv_data'].append(
                create_finding(
                    finding_name="Marketplace Subscription Access Check",
                    finding_details="No identities found with overly permissive marketplace subscription access",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html#security-iam-awsmanpol-bedrock-marketplace",
                    severity='N/A',
                    status='Passed'
                ))

        return findings

    except Exception as e:
        logger.error(f"Error in check_marketplace_subscription_access: {str(e)}", exc_info=True)
        return {
            'check_name': 'Marketplace Subscription Access Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def has_bedrock_access(iam_client, principal_name: str, principal_type: str) -> bool:
    """
    Check if a user or role has Bedrock access through policies
    """
    logger.debug(f"Checking Bedrock access for {principal_type}: {principal_name}")
    try:
        if principal_type == 'role':
            policies = iam_client.list_attached_role_policies(RoleName=principal_name)
        else:
            policies = iam_client.list_attached_user_policies(UserName=principal_name)

        # Check attached policies
        for policy in policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            logger.debug(f"Checking policy: {policy_arn}")
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_doc = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version
            )['PolicyVersion']['Document']

            if has_bedrock_permissions(policy_doc):
                logger.info(f"Found Bedrock permissions in policy: {policy_arn}")
                return True

        # Check inline policies
        if principal_type == 'role':
            inline_policies = iam_client.list_role_policies(RoleName=principal_name)
        else:
            inline_policies = iam_client.list_user_policies(UserName=principal_name)

        for policy_name in inline_policies['PolicyNames']:
            logger.debug(f"Checking inline policy: {policy_name}")
            if principal_type == 'role':
                policy_doc = iam_client.get_role_policy(
                    RoleName=principal_name,
                    PolicyName=policy_name
                )['PolicyDocument']
            else:
                policy_doc = iam_client.get_user_policy(
                    UserName=principal_name,
                    PolicyName=policy_name
                )['PolicyDocument']

            if has_bedrock_permissions(policy_doc):
                logger.info(f"Found Bedrock permissions in inline policy: {policy_name}")
                return True

        return False

    except Exception as e:
        logger.error(f"Error checking permissions for {principal_type} {principal_name}: {str(e)}")
        return False

def check_stale_bedrock_access(permission_cache) -> Dict[str, Any]:
    logger.debug("Starting check for stale Bedrock access")
    try:
        findings = {
            'check_name': 'Stale Bedrock Access Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        stale_identities = []
        active_identities = []
        two_months_ago = datetime.now(timezone.utc) - timedelta(days=60)

        sts_client = boto3.client('sts', config=boto3_config)
        account_id = sts_client.get_caller_identity()['Account']

        identities_to_check = []
        
        # Check roles
        for role_name, permissions in permission_cache["role_permissions"].items():
            if has_bedrock_permissions_in_cache(permissions):
                identities_to_check.append(('role', role_name))

        # Check users
        for user_name, permissions in permission_cache["user_permissions"].items():
            if has_bedrock_permissions_in_cache(permissions):
                identities_to_check.append(('user', user_name))

        if not identities_to_check:
            logger.info("No identities found with Bedrock access")
            findings['csv_data'].append(
                create_finding(
                    finding_name="Stale Bedrock Access Check",
                    finding_details="No identities found with Bedrock access",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity='N/A',
                    status='Passed'
                )
            )
            return findings

        # Check last accessed info for each identity
        iam_client = boto3.client('iam', config=boto3_config)
        for identity_type, identity_name in identities_to_check:
            try:
                arn = f"arn:aws:iam::{account_id}:{identity_type}/{identity_name}"
                response = iam_client.generate_service_last_accessed_details(Arn=arn)
                job_id = response['JobId']
                
                wait_time = 0
                max_wait_time = 30
                while wait_time < max_wait_time:
                    response = iam_client.get_service_last_accessed_details(JobId=job_id)
                    if response['JobStatus'] == 'COMPLETED':
                        for service in response['ServicesLastAccessed']:
                            if service['ServiceName'] == 'Amazon Bedrock':
                                last_accessed = service.get('LastAuthenticated')
                                if last_accessed:
                                    if last_accessed.replace(tzinfo=timezone.utc) < two_months_ago:
                                        stale_identities.append({
                                            'name': identity_name,
                                            'type': identity_type,
                                            'last_accessed': last_accessed
                                        })
                                    else:
                                        active_identities.append({
                                            'name': identity_name,
                                            'type': identity_type,
                                            'last_accessed': last_accessed
                                        })
                                else:
                                    stale_identities.append({
                                        'name': identity_name,
                                        'type': identity_type,
                                        'last_accessed': None
                                    })
                        break
                    time.sleep(1)
                    wait_time += 1
            except Exception as e:
                logger.error(f"Error checking last access for {identity_type} {identity_name}: {str(e)}")
                continue

        if stale_identities:
            findings['status'] = 'WARN'
            findings['details'] = f"Found {len(stale_identities)} identities with stale Bedrock access"
            
            for identity in stale_identities:
                last_accessed_str = identity['last_accessed'].strftime('%Y-%m-%d') if identity['last_accessed'] else 'never'
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Stale Bedrock Access Check",
                        finding_details=f"{identity['type'].capitalize()} '{identity['name']}' last accessed Bedrock on {last_accessed_str}",
                        resolution="You can use last accessed information to refine your policies and allow access to only the services and actions that your IAM identities and policies use. This helps you to better adhere to the best practice of least privilege.",
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                        severity='Medium',
                        status='Failed'
                    )
                )
                
        else:
            active_details = []
            for identity in active_identities:
                last_accessed_str = identity['last_accessed'].strftime('%Y-%m-%d')
                active_details.append(f"{identity['type'].capitalize()} '{identity['name']}' last accessed on {last_accessed_str}")
            
            finding_details = "All identities with Bedrock access are actively using the service"
            if active_details:
                finding_details += ": " + "; ".join(active_details)
            
            findings['details'] = finding_details
            findings['csv_data'].append(
                create_finding(
                    finding_name="Stale Bedrock Access Check",
                    finding_details=finding_details,
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity='N/A',
                    status='Passed'
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_stale_bedrock_access: {str(e)}", exc_info=True)
        return {
            'check_name': 'Stale Bedrock Access Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def check_bedrock_full_access_roles(permission_cache) -> Dict[str, Any]:
    """
    Check for roles with AmazonBedrockFullAccess policy using cached permissions
    """
    logger.debug("Starting check for AmazonBedrockFullAccess roles")
    findings = {
        'check_name': 'Bedrock Full Access Check',
        'status': 'PASS',
        'details': '',
        'csv_data': []
    }

    bedrock_roles = []
    for role_name, permissions in permission_cache["role_permissions"].items():
        for policy in permissions['attached_policies']:
            if policy['name'] == 'AmazonBedrockFullAccess':
                bedrock_roles.append({
                    'name': role_name,
                    'policy': policy['name']
                })
                break

    if bedrock_roles:
        findings['status'] = 'WARN'
        findings['details'] = f"Found {len(bedrock_roles)} roles with AmazonBedrockFullAccess policy"
        
        for role in bedrock_roles:
            findings['csv_data'].append(
                create_finding(
                    finding_name="AmazonBedrockFullAccess role check",
                    finding_details=f"Role '{role['name']}' has AmazonBedrockFullAccess policy attached",
                    resolution="Limit the AmazonBedrockFullAccess policy only to required access",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html#iam-agents-ex-all\nhttps://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-br-studio.html",
                    severity='High',
                    status='Failed'
                )
            )
    else:
        findings['details'] = "No roles found with AmazonBedrockFullAccess policy"
        findings['csv_data'].append(
            create_finding(
                finding_name="AmazonBedrockFullAccess role check",
                finding_details="No roles found with AmazonBedrockFullAccess policy",
                resolution="No action required",
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html#iam-agents-ex-all\nhttps://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-br-studio.html",
                severity='N/A',
                status='Passed'
            )
        )

    return findings

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

def check_bedrock_vpc_endpoints() -> Dict[str, bool]:
    """
    Check if any VPC has Bedrock VPC endpoints
    """
    logger.debug("Checking for Bedrock VPC endpoints")
    try:
        ec2_client = boto3.client('ec2', config=boto3_config)
        
        bedrock_endpoints = [
            'com.amazonaws.region.bedrock',
            'com.amazonaws.region.bedrock-runtime',
            'com.amazonaws.region.bedrock-agent',
            'com.amazonaws.region.bedrock-agent-runtime'
        ]

        # Get current region
        session = boto3.session.Session()
        current_region = session.region_name
        logger.debug(f"Current region: {current_region}")

        # Get list of all VPCs
        vpcs = ec2_client.describe_vpcs()
        vpc_ids = [vpc['VpcId'] for vpc in vpcs['Vpcs']]
        logger.debug(f"Found VPCs: {vpc_ids}")
        
        # Replace 'region' with actual region in endpoint names
        bedrock_endpoints = [endpoint.replace('region', current_region) for endpoint in bedrock_endpoints]
        found_endpoints = []
        
        # Get all VPC endpoints
        paginator = ec2_client.get_paginator('describe_vpc_endpoints')
        
        for page in paginator.paginate():
            for endpoint in page['VpcEndpoints']:
                service_name = endpoint['ServiceName']
                vpc_id = endpoint['VpcId']
                logger.debug(f"Found VPC endpoint: {service_name} in VPC: {vpc_id}")
                
                # Check if this endpoint matches any of our Bedrock endpoints
                for bedrock_endpoint in bedrock_endpoints:
                    if service_name == bedrock_endpoint:
                        logger.info(f"Found matching Bedrock endpoint: {service_name} in VPC: {vpc_id}")
                        found_endpoints.append({
                            'vpc_id': vpc_id,
                            'service': service_name
                        })
        
        return {
            'has_endpoints': len(found_endpoints) > 0,
            'found_endpoints': found_endpoints,
            'all_vpcs': vpc_ids
        }

    except Exception as e:
        logger.error(f"Error checking VPC endpoints: {str(e)}", exc_info=True)
        return {
            'has_endpoints': False,
            'found_endpoints': [],
            'all_vpcs': []
        }

def has_bedrock_permissions_in_cache(permissions: Dict) -> bool:
    """
    Check if the cached permissions contain Bedrock access
    """
    for policy in permissions['attached_policies'] + permissions['inline_policies']:
        if has_bedrock_permissions(policy['document']):
            return True
    return False

def has_bedrock_permissions(policy_doc: Any) -> bool:
    """
    Check if a policy document contains Bedrock permissions
    """
    try:
        if isinstance(policy_doc, str):
            policy_doc = json.loads(policy_doc)

        if not policy_doc:
            return False

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
                if 'bedrock' in action.lower():
                    return True

        return False
    except Exception as e:
        logger.error(f"Error parsing policy document: {str(e)}")
        return False

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

def has_bedrock_permissions(policy_doc: Dict) -> bool:
    """
    Check if a policy document contains Bedrock permissions
    """
    logger.debug("Checking policy document for Bedrock permissions")
    try:
        # Handle string input by converting to dict
        if isinstance(policy_doc, str):
            import json
            policy_doc = json.loads(policy_doc)
            
        for statement in policy_doc.get('Statement', []):
            action = statement.get('Action', [])
            if isinstance(action, str):
                action = [action]
            
            for act in action:
                if 'bedrock' in act.lower():
                    effect = statement.get('Effect', '')
                    if effect.upper() == 'ALLOW':
                        logger.debug(f"Found Bedrock permission: {act}")
                        return True
        
        return False
    except Exception as e:
        logger.error(f"Error parsing policy document: {str(e)}")
        return False

def check_bedrock_access_and_vpc_endpoints(permission_cache) -> Dict[str, Any]:
    logger.debug("Starting check for Bedrock access and VPC endpoints")
    try:
        findings = {
            'check_name': 'Bedrock Access and VPC Endpoint Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        bedrock_access_found = False
        
        # Check roles and users for Bedrock access
        for role_name, permissions in permission_cache["role_permissions"].items():
            if has_bedrock_permissions_in_cache(permissions):
                bedrock_access_found = True
                break

        if not bedrock_access_found:
            for user_name, permissions in permission_cache["user_permissions"].items():
                if has_bedrock_permissions_in_cache(permissions):
                    bedrock_access_found = True
                    break

        if bedrock_access_found:
            vpc_endpoint_check = check_bedrock_vpc_endpoints()
            
            if not vpc_endpoint_check['has_endpoints']:
                findings['status'] = 'WARN'
                
                if vpc_endpoint_check['all_vpcs']:
                    vpc_list = ', '.join(vpc_endpoint_check['all_vpcs'])
                    finding_detail = f"No Bedrock service VPC endpoints found in VPCs: {vpc_list}"
                else:
                    finding_detail = "No VPCs found in the account"
                
                findings['csv_data'].append(
                    create_finding(
                        finding_name='Amazon Bedrock private connectivity not used',
                        finding_details=finding_detail,
                        resolution='Create a VPC endpoint in your VPC with any of the following Bedrock service endpoints that your application may be using:\n- com.amazonaws.region.bedrock\n- com.amazonaws.region.bedrock-runtime\n- com.amazonaws.region.bedrock-agent\n- com.amazonaws.region.bedrock-agent-runtime',
                        reference='https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html',
                        severity='Medium',
                        status='Failed'
                    )
                    )
            else:
                endpoint_details = []
                for endpoint in vpc_endpoint_check['found_endpoints']:
                    endpoint_details.append(f"VPC {endpoint['vpc_id']} has endpoint {endpoint['service']}")
                findings['details'] = "Bedrock VPC endpoints found: " + "; ".join(endpoint_details)
        else:
            findings['details'] = "No Bedrock access found in roles or users"

        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_access_and_vpc_endpoints: {str(e)}", exc_info=True)
        return {
            'check_name': 'Bedrock Access and VPC Endpoint Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }
    
def check_bedrock_guardrails() -> Dict[str, Any]:
    """
    Check if Amazon Bedrock Guardrails are configured and being used
    """
    logger.debug("Starting check for Bedrock Guardrails configuration")
    try:
        findings = {
            'check_name': 'Bedrock Guardrails Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        bedrock_client = boto3.client('bedrock', config=boto3_config)
        
        try:
            # List all guardrails
            response = bedrock_client.list_guardrails()
            
            if response.get('guardrails', []):
                guardrail_names = [guardrail['name'] for guardrail in response['guardrails']]
                findings['details'] = f"Found {len(guardrail_names)} Bedrock guardrails configured"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Guardrails Check",
                        finding_details=f"Amazon Bedrock Guardrails are properly configured with {len(guardrail_names)} guardrails",
                        resolution="No action required. Continue monitoring and updating guardrails as needed.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                        severity='N/A',
                        status='Passed'
                    )
                )
            else:
                findings['status'] = 'WARN'
                findings['details'] = "No Bedrock guardrails configured"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Guardrails Check",
                        finding_details="No Amazon Bedrock Guardrails are configured. This may expose your application to potential risks such as harmful content, sensitive information disclosure, or hallucinations.",
                        resolution="Configure Bedrock Guardrails to implement safeguards such as:\n- Content filters to block harmful content\n- Denied topics to prevent undesirable discussions\n- Sensitive information filters to protect PII\n- Contextual grounding checks to prevent hallucinations",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                        severity='Medium',
                        status='Failed'
                    )
                )

            # Check if guardrails are actually being used in any model invocations
            if response.get('guardrails', []):
                try:
                    # Get a sample of recent invocations to check for guardrail usage
                    model_invocations = bedrock_client.list_model_invocations(
                        maxResults=20,  # Sample size
                        filters={
                            'createdAfter': (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
                        }
                    )
                    
                    guardrail_usage_found = False
                    for invocation in model_invocations.get('modelInvocations', []):
                        if invocation.get('guardrailConfiguration'):
                            guardrail_usage_found = True
                            break
                    
                    if not guardrail_usage_found:
                        findings['status'] = 'WARN'
                        findings['csv_data'].append(
                            create_finding(
                                finding_name="Bedrock Guardrails Usage Check",
                                finding_details="Guardrails are configured but not detected in recent model invocations. This suggests guardrails may not be actively enforced.",
                                resolution="Ensure guardrails are properly integrated into your application code using the ApplyGuardrail API or through Bedrock Agents and Knowledge Bases.",
                                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                                severity='Low',
                                status='Failed'
                            )
                        )
                except Exception as e:
                    logger.warning(f"Could not check guardrail usage in invocations: {str(e)}")
                
        except bedrock_client.exceptions.ValidationException as e:
            findings['status'] = 'ERROR'
            findings['details'] = f"Error validating guardrails configuration: {str(e)}"
            findings['csv_data'].append(
                create_finding(
                    finding_name="Bedrock Guardrails Check",
                    finding_details=f"Error checking Bedrock Guardrails configuration: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access Bedrock Guardrails.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                    severity='High',
                    status='Failed'
                )
            )
            
        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_guardrails: {str(e)}", exc_info=True)
        return {
            'check_name': 'Bedrock Guardrails Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }


def check_bedrock_logging_configuration() -> Dict[str, Any]:
    """
    Check if model invocation logging is enabled for Amazon Bedrock
    """
    logger.debug("Starting check for Bedrock model invocation logging configuration")
    try:
        findings = {
            'check_name': 'Bedrock Model Invocation Logging Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        bedrock_client = boto3.client('bedrock', config=boto3_config)
        
        try:
            # Get current logging configuration
            response = bedrock_client.get_model_invocation_logging_configuration()
            
            logging_enabled = False
            enabled_destinations = []
            
            # Check S3 logging configuration
            s3_config = response.get('loggingConfig', {}).get('s3Config')
            if s3_config and s3_config.get('s3BucketName'):
                logging_enabled = True
                enabled_destinations.append('Amazon S3')
            
            # Check CloudWatch logging configuration
            cloudwatch_config = response.get('loggingConfig', {}).get('cloudWatchConfig')
            if cloudwatch_config and cloudwatch_config.get('logGroupName'):
                logging_enabled = True
                enabled_destinations.append('CloudWatch Logs')
            
            if logging_enabled:
                findings['details'] = f"Model invocation logging is enabled with delivery to: {', '.join(enabled_destinations)}"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Model Invocation Logging Check",
                        finding_details=f"Model invocation logging is properly configured with delivery to: {', '.join(enabled_destinations)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                        severity='N/A',
                        status='Passed'
                    )
                )
            else:
                findings['status'] = 'FAIL'
                findings['details'] = "Model invocation logging is not enabled"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Model Invocation Logging Check",
                        finding_details="Model invocation logging is not enabled. This limits your ability to track and audit model usage.",
                        resolution="Enable model invocation logging to collect invocation logs, model input data, and model output data. Configure logging to deliver to Amazon S3, CloudWatch Logs, or both for comprehensive monitoring.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                        severity='Medium',
                        status='Failed'
                    )
                )
                
        except bedrock_client.exceptions.ValidationException:
            findings['status'] = 'FAIL'
            findings['details'] = "Model invocation logging is not enabled"
            findings['csv_data'].append(
                create_finding(
                    finding_name="Bedrock Model Invocation Logging Check",
                    finding_details="Model invocation logging is not enabled. This limits your ability to track and audit model usage.",
                    resolution="Enable model invocation logging to collect invocation logs, model input data, and model output data. Configure logging to deliver to Amazon S3, CloudWatch Logs, or both for comprehensive monitoring.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                    severity='Medium',
                    status='Failed'
                )
            )
            
        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_logging_configuration: {str(e)}", exc_info=True)
        return {
            'check_name': 'Bedrock Model Invocation Logging Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def check_bedrock_cloudtrail_logging() -> Dict[str, Any]:
    """
    Check if CloudTrail is configured to log Amazon Bedrock API calls
    """
    logger.debug("Starting check for Bedrock CloudTrail logging configuration")
    try:
        findings = {
            'check_name': 'Bedrock CloudTrail Logging Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        cloudtrail_client = boto3.client('cloudtrail', config=boto3_config)
        
        try:
            # Get all trails
            trails_response = cloudtrail_client.list_trails()
            trails = trails_response.get('Trails', [])
            
            bedrock_logging_enabled = False
            logging_trails = []
            
            for trail in trails:
                trail_arn = trail['TrailARN']
                trail_name = trail['Name']
                
                # Get trail configuration
                trail_config = cloudtrail_client.get_trail(Name=trail_arn)
                
                # Check if trail is enabled and multi-region
                if trail_config['Trail'].get('IsMultiRegionTrail') and \
                   trail_config['Trail'].get('IsLogging', False):
                    
                    # Get event selectors
                    event_selectors = cloudtrail_client.get_event_selectors(
                        TrailName=trail_arn
                    )
                    
                    # Check advanced event selectors if they exist
                    advanced_selectors = event_selectors.get('AdvancedEventSelectors', [])
                    basic_selectors = event_selectors.get('EventSelectors', [])
                    
                    # Check if Bedrock events are being logged
                    for selector in advanced_selectors:
                        field_selectors = selector.get('FieldSelectors', [])
                        for field in field_selectors:
                            if field.get('Field') == 'eventSource' and \
                               'bedrock' in str(field.get('Equals', [])).lower():
                                bedrock_logging_enabled = True
                                logging_trails.append(trail_name)
                                break
                    
                    # If no advanced selectors, check if logging all management events
                    if not bedrock_logging_enabled and basic_selectors:
                        for selector in basic_selectors:
                            if selector.get('IncludeManagementEvents', False) and \
                               selector.get('ReadWriteType', '') in ['All', 'Write']:
                                bedrock_logging_enabled = True
                                logging_trails.append(trail_name)
                                break
            
            if bedrock_logging_enabled:
                findings['details'] = f"CloudTrail logging enabled for Bedrock in trails: {', '.join(logging_trails)}"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock CloudTrail Logging Check",
                        finding_details=f"CloudTrail is properly configured to log Bedrock API activity in trails: {', '.join(logging_trails)}",
                        resolution="No action required. Continue monitoring CloudTrail logs for Bedrock activity.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                        severity='N/A',
                        status='Passed'
                    )
                )
            else:
                findings['status'] = 'FAIL'
                findings['details'] = "No CloudTrail trails configured to log Bedrock activity"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock CloudTrail Logging Check",
                        finding_details="CloudTrail is not configured to log Amazon Bedrock API calls. This limits your ability to audit and monitor Bedrock usage.",
                        resolution="Enable CloudTrail logging for Bedrock by either:\n" + 
                                 "1. Configuring an advanced event selector for Bedrock events, or\n" +
                                 "2. Enabling management events logging in a multi-region trail",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                        severity='High',
                        status='Failed'
                    )
                )

        except cloudtrail_client.exceptions.ClientError as e:
            findings['status'] = 'ERROR'
            findings['details'] = f"Error checking CloudTrail configuration: {str(e)}"
            findings['csv_data'].append(
                create_finding(
                    finding_name="Bedrock CloudTrail Logging Check",
                    finding_details=f"Error checking CloudTrail configuration for Bedrock logging: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access CloudTrail.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                    severity='High',
                    status='Failed'
                )
            )
            
        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_cloudtrail_logging: {str(e)}", exc_info=True)
        return {
            'check_name': 'Bedrock CloudTrail Logging Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }
    
def check_bedrock_prompt_management() -> Dict[str, Any]:
    """
    Check if Amazon Bedrock Prompt Management feature is being used
    """
    logger.debug("Starting check for Bedrock Prompt Management usage")
    try:
        findings = {
            'check_name': 'Bedrock Prompt Management Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        bedrock_client = boto3.client('bedrock-agent', config=boto3_config)
        
        try:
            # List all prompts
            response = bedrock_client.list_prompts()
            prompts = response.get('promptSummaries', [])
            
            if prompts:
                # Count prompts by status
                active_prompts = [p for p in prompts if p.get('status') == 'ACTIVE']
                draft_prompts = [p for p in prompts if p.get('status') == 'DRAFT']
                
                findings['details'] = f"Found {len(prompts)} prompts ({len(active_prompts)} active, {len(draft_prompts)} draft)"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Prompt Management Check",
                        finding_details=f"Prompt Management is being used with {len(prompts)} prompts ({len(active_prompts)} active, {len(draft_prompts)} draft)",
                        resolution="No action required. Continue using Prompt Management for consistent and optimized prompts.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                        severity='N/A',
                        status='Passed'
                    )
                )
                
                # Additional check for prompt variants
                prompts_without_variants = []
                for prompt in prompts:
                    try:
                        prompt_details = bedrock_client.get_prompt(
                            promptId=prompt['promptId']
                        )
                        if len(prompt_details.get('variants', [])) <= 1:
                            prompts_without_variants.append(prompt['name'])
                    except Exception as e:
                        logger.warning(f"Could not get details for prompt {prompt['name']}: {str(e)}")
                
                if prompts_without_variants:
                    findings['status'] = 'WARN'
                    findings['csv_data'].append(
                        create_finding(
                            finding_name="Bedrock Prompt Variants Check",
                            finding_details=f"Found {len(prompts_without_variants)} prompts without multiple variants. Testing different prompt variants helps optimize responses.",
                            resolution="Create and test multiple variants for your prompts to find the most effective configurations.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                            severity='N/A',
                            status='N/A'
                        )
                    )
            else:
                findings['status'] = 'WARN'
                findings['details'] = "Prompt Management feature is not being used"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Prompt Management Check",
                        finding_details="Prompt Management feature is not being used. This may lead to inconsistent prompt handling and suboptimal model responses.",
                        resolution="Implement Prompt Management to:\n" +
                                 "1. Create and version your prompts\n" +
                                 "2. Test different prompt variants\n" +
                                 "3. Share prompts across your organization\n" +
                                 "4. Maintain consistent prompt templates",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                        severity='N/A',
                        status='N/A'
                    )
                )

        except bedrock_client.exceptions.ValidationException as e:
            findings['status'] = 'ERROR'
            findings['details'] = f"Error checking Prompt Management: {str(e)}"
            findings['csv_data'].append(
                create_finding(
                    finding_name="Bedrock Prompt Management Check",
                    finding_details=f"Error checking Bedrock Prompt Management configuration: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access Bedrock Prompt Management.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                    severity='High',
                    status='Failed'
                )
            )
            
        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_prompt_management: {str(e)}", exc_info=True)
        return {
            'check_name': 'Bedrock Prompt Management Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

def check_bedrock_agent_roles(permission_cache) -> Dict[str, Any]:
    """
    Check IAM roles associated with Bedrock agents for least privilege access
    """
    logger.debug("Starting check for Bedrock agent IAM roles")
    try:
        findings = {
            'check_name': 'Bedrock Agent IAM Roles Check',
            'status': 'PASS',
            'details': '',
            'csv_data': []
        }

        bedrock_client = boto3.client('bedrock-agent', config=boto3_config)
        
        try:
            # Get all Bedrock agents
            response = bedrock_client.list_agents()
            agents = response.get('agents', [])
            
            if not agents:
                findings['details'] = "No Bedrock agents found"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Agent IAM Roles Check",
                        finding_details="No Bedrock agents found in the account",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_service-with-iam.html",
                        severity='N/A',
                        status='Passed'
                    )
                )
                return findings

            issues_found = []
            
            for agent in agents:
                agent_id = agent.get('agentId')
                agent_name = agent.get('agentName')
                
                # Get agent details including role ARN
                agent_details = bedrock_client.get_agent(
                    agentId=agent_id
                )
                
                role_arn = agent_details.get('agentResourceRoleArn')
                if not role_arn:
                    continue
                
                role_name = role_arn.split('/')[-1]
                
                # Check role in permission cache
                if role_name in permission_cache["role_permissions"]:
                    role_info = permission_cache["role_permissions"][role_name]
                    
                    # Check for overly permissive policies
                    has_full_access = False
                    has_permission_boundary = bool(role_info.get('permission_boundary'))
                    has_vpc_condition = False
                    has_specific_resources = True
                    
                    # Check attached policies
                    for policy in role_info['attached_policies']:
                        if 'BedrockFullAccess' in policy['name']:
                            has_full_access = True
                        
                        # Check policy document for resource constraints and conditions
                        doc = policy.get('document', {})
                        for statement in doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                # Check for resource constraints
                                resources = statement.get('Resource', [])
                                if resources == ['*']:
                                    has_specific_resources = False
                                
                                # Check for VPC conditions
                                conditions = statement.get('Condition', {})
                                if any('vpc' in str(c).lower() for c in conditions.values()):
                                    has_vpc_condition = True
                    
                    # Check inline policies
                    for policy in role_info['inline_policies']:
                        doc = policy.get('document', {})
                        for statement in doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                resources = statement.get('Resource', [])
                                if resources == ['*']:
                                    has_specific_resources = False
                                
                                conditions = statement.get('Condition', {})
                                if any('vpc' in str(c).lower() for c in conditions.values()):
                                    has_vpc_condition = True
                    
                    # Collect issues
                    role_issues = []
                    if has_full_access:
                        role_issues.append("uses full access policy")
                    if not has_specific_resources:
                        role_issues.append("lacks specific resource constraints")
                    if not has_permission_boundary:
                        role_issues.append("missing permission boundary")
                    if not has_vpc_condition:
                        role_issues.append("missing VPC conditions")
                    
                    if role_issues:
                        issues_found.append(f"Agent '{agent_name}' role '{role_name}' {', '.join(role_issues)}")
            
            if issues_found:
                findings['status'] = 'FAIL'
                findings['details'] = f"Found {len(issues_found)} roles with least privilege issues"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Agent IAM Roles Check",
                        finding_details=f"IAM roles associated with Bedrock agents have least privilege issues:\n" + 
                                      "\n".join(f"- {issue}" for issue in issues_found),
                        resolution="1. Replace full access policies with scoped policies\n" +
                                 "2. Specify exact resource ARNs instead of using wildcards\n" +
                                 "3. Apply permission boundaries to limit maximum permissions\n" +
                                 "4. Add VPC conditions to restrict access to specific networks\n" +
                                 "5. Review and update role trust policies",
                        reference="https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html",
                        severity='High',
                        status='Failed'
                    )
                )
            else:
                findings['details'] = f"All {len(agents)} Bedrock agent roles follow least privilege principles"
                findings['csv_data'].append(
                    create_finding(
                        finding_name="Bedrock Agent IAM Roles Check",
                        finding_details=f"All {len(agents)} Bedrock agent roles properly implement least privilege access",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html",
                        severity='N/A',
                        status='Passed'
                    )
                )

        except bedrock_client.exceptions.ValidationException as e:
            findings['status'] = 'ERROR'
            findings['details'] = f"Error checking Bedrock agents: {str(e)}"
            findings['csv_data'].append(
                create_finding(
                    finding_name="Bedrock Agent IAM Roles Check",
                    finding_details=f"Error checking Bedrock agent configurations: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access Bedrock agents.",
                    reference="https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html",
                    severity='High',
                    status='Failed'
                )
            )
            
        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_agent_roles: {str(e)}", exc_info=True)
        return {
            'check_name': 'Bedrock Agent IAM Roles Check',
            'status': 'ERROR',
            'details': f"Error during check: {str(e)}",
            'csv_data': []
        }

    
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

def write_to_s3(execution_id, csv_content: str, bucket_name: str) -> str:
    """
    Write CSV report to S3 bucket
    """
    logger.debug(f"Writing CSV report to S3 bucket: {bucket_name}")
    try:
        s3_client = boto3.client('s3', config=boto3_config)
        file_name = f'bedrock_security_report_{execution_id}.csv'
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=file_name,
            Body=csv_content,
            ContentType='text/csv'
        )
        
        s3_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
        logger.info(f"Successfully wrote report to S3: {s3_url}")
        return s3_url
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
        
        if not permission_cache:
            logger.error("Permission cache not found - IAM permission caching may have failed")
            permission_cache = {"role_permissions": {}, "user_permissions": {}}
        
        # Run all checks using the cached permissions
        logger.info("Running AmazonBedrockFullAccess check")
        bedrock_full_access_findings = check_bedrock_full_access_roles(permission_cache)
        all_findings.append(bedrock_full_access_findings)
        
        logger.info("Running Bedrock access and VPC endpoints check")
        bedrock_access_vpc_findings = check_bedrock_access_and_vpc_endpoints(permission_cache)
        all_findings.append(bedrock_access_vpc_findings)
        
        #logger.info("Running stale access check")
        #stale_access_findings = check_stale_bedrock_access(permission_cache)
        #all_findings.append(stale_access_findings)
        
        logger.info("Running marketplace subscription access check")
        marketplace_access_findings = check_marketplace_subscription_access(permission_cache)
        all_findings.append(marketplace_access_findings)
        
        logger.info("Running Bedrock logging findings check")
        bedrock_logging_findings = check_bedrock_logging_configuration()
        all_findings.append(bedrock_logging_findings)

        logger.info("Running Bedrock Guardrails check")
        bedrock_guardrails_findings = check_bedrock_guardrails()
        all_findings.append(bedrock_guardrails_findings)

        logger.info("Running Bedrock CloudTrail logging check")
        bedrock_cloudtrail_findings = check_bedrock_cloudtrail_logging()
        all_findings.append(bedrock_cloudtrail_findings)

        logger.info("Running Bedrock Prompt Management check")
        bedrock_prompt_management_findings = check_bedrock_prompt_management()
        all_findings.append(bedrock_prompt_management_findings)

        logger.info("Running Bedrock agent IAM roles check")
        bedrock_agent_roles_findings = check_bedrock_agent_roles(permission_cache)
        all_findings.append(bedrock_agent_roles_findings)
        
        # Generate and upload report
        logger.info("Generating CSV report")
        csv_content = generate_csv_report(all_findings)
        
        bucket_name = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')
        if not bucket_name:
            raise ValueError("AIML_ASSESSMENT_BUCKET_NAME environment variable is not set")
        
        logger.info("Writing report to S3")
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
