import boto3
import csv
import os
import logging
from datetime import datetime, timedelta, timezone
import time
from typing import Dict, List, Any, Optional
from io import StringIO
import asyncio
import json
from botocore.config import Config
from botocore.exceptions import ClientError
import random

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

def write_permissions_to_s3(permission_cache, execution_id):
    """
    Write the IAM permissions cache to S3 as a JSON file
    
    Args:
        permission_cache (IAMPermissionCache): The permission cache object
        s3_bucket (str): The name of the S3 bucket to write to
    """
    try:
        # Create S3 client with the same retry configuration
        s3_client = boto3.client('s3', config=boto3_config)
        
        # Prepare the data to be written
        cache_data = {
            'role_permissions': permission_cache.role_permissions,
            'user_permissions': permission_cache.user_permissions,
            'generated_at': datetime.now().isoformat()
        }
        
        # Convert to JSON string
        json_data = json.dumps(cache_data, default=str, indent=2)
        
        # Define the S3 key (filename)
        s3_key = f'{execution_id}/permissions_cache.json'
        s3_bucket = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')

        # Upload to S3
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=json_data,
            ContentType='application/json'
        )
        
        logger.info(f"Successfully wrote permissions cache to s3://{s3_bucket}/{s3_key}")
        return s3_key
        
    except Exception as e:
        logger.error(f"Error writing permissions cache to S3: {str(e)}", exc_info=True)
        raise

class IAMPermissionCache:
    def __init__(self, iam_client):
        self.iam_client = iam_client
        self.role_permissions = {}
        self.user_permissions = {}
        self.policy_cache = {}
        
    def initialize(self):
        """
        Get all IAM permissions and cache them
        """
        logger.info("Initializing IAM permission cache")
        self._cache_role_permissions()
        self._cache_user_permissions()
        
    def _get_policy_document(self, policy_arn, version_id):
        """
        Get policy document with caching
        """
        cache_key = f"{policy_arn}:{version_id}"
        if cache_key not in self.policy_cache:
            try:
                response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                self.policy_cache[cache_key] = response['PolicyVersion']['Document']
            except Exception as e:
                logger.error(f"Error getting policy document for {policy_arn}: {str(e)}")
                return None
        return self.policy_cache[cache_key]

    def _cache_role_permissions(self):
        """
        Cache all role permissions
        """
        logger.info("Caching role permissions")
        paginator = self.iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                self.role_permissions[role_name] = {
                    'attached_policies': [],
                    'inline_policies': []
                }
                
                # Get attached policies
                try:
                    attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies['AttachedPolicies']:
                        policy_arn = policy['PolicyArn']
                        try:
                            policy_info = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']
                            policy_doc = self._get_policy_document(policy_arn, policy_info['DefaultVersionId'])
                            if policy_doc:
                                self.role_permissions[role_name]['attached_policies'].append({
                                    'name': policy['PolicyName'],
                                    'arn': policy_arn,
                                    'document': policy_doc
                                })
                        except Exception as e:
                            logger.error(f"Error getting policy {policy_arn}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error getting attached policies for role {role_name}: {str(e)}")

                # Get inline policies
                try:
                    inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
                    for policy_name in inline_policies['PolicyNames']:
                        try:
                            policy_doc = self.iam_client.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            )['PolicyDocument']
                            self.role_permissions[role_name]['inline_policies'].append({
                                'name': policy_name,
                                'document': policy_doc
                            })
                        except Exception as e:
                            logger.error(f"Error getting inline policy {policy_name}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error getting inline policies for role {role_name}: {str(e)}")

    def _cache_user_permissions(self):
        """
        Cache all user permissions
        """
        logger.info("Caching user permissions")
        paginator = self.iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                self.user_permissions[user_name] = {
                    'attached_policies': [],
                    'inline_policies': []
                }
                
                # Get attached policies
                try:
                    attached_policies = self.iam_client.list_attached_user_policies(UserName=user_name)
                    for policy in attached_policies['AttachedPolicies']:
                        policy_arn = policy['PolicyArn']
                        try:
                            policy_info = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']
                            policy_doc = self._get_policy_document(policy_arn, policy_info['DefaultVersionId'])
                            if policy_doc:
                                self.user_permissions[user_name]['attached_policies'].append({
                                    'name': policy['PolicyName'],
                                    'arn': policy_arn,
                                    'document': policy_doc
                                })
                        except Exception as e:
                            logger.error(f"Error getting policy {policy_arn}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error getting attached policies for user {user_name}: {str(e)}")

                # Get inline policies
                try:
                    inline_policies = self.iam_client.list_user_policies(UserName=user_name)
                    for policy_name in inline_policies['PolicyNames']:
                        try:
                            policy_doc = self.iam_client.get_user_policy(
                                UserName=user_name,
                                PolicyName=policy_name
                            )['PolicyDocument']
                            self.user_permissions[user_name]['inline_policies'].append({
                                'name': policy_name,
                                'document': policy_doc
                            })
                        except Exception as e:
                            logger.error(f"Error getting inline policy {policy_name}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error getting inline policies for user {user_name}: {str(e)}")
    
def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Starting Bedrock security assessment")
    iam_client = boto3.client('iam', config=boto3_config)
    logger.info(event, context)
    try:
        # Initialize permission cache
        logger.info("Initializing IAM permission cache")
        permission_cache = IAMPermissionCache(iam_client)
        permission_cache.initialize()
        execution_id = event["Execution"]["Name"]
        write_permissions_to_s3(permission_cache, execution_id)

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': f'Error during security checks: {str(e)}'
        }
