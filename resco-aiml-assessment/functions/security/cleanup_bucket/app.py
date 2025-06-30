import boto3
import os
import logging
from botocore.config import Config
from botocore.exceptions import ClientError

# Configure boto3 with retries
boto3_config = Config(
    retries = dict(
        max_attempts = 10,
        mode = 'adaptive'
    )
)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Clean up old assessment reports from S3 bucket
    """
    logger.info("Starting S3 bucket cleanup")
    
    try:
        bucket_name = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')
        if not bucket_name:
            raise ValueError("AIML_ASSESSMENT_BUCKET_NAME environment variable is not set")
        
        s3_client = boto3.client('s3', config=boto3_config)
        
        # List all objects in the bucket
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        
        if 'Contents' in response:
            objects_to_delete = []
            for obj in response['Contents']:
                # Delete CSV, HTML and JSON files
                if obj['Key'].endswith(('.csv', '.html', '.json')):
                    objects_to_delete.append({'Key': obj['Key']})
            
            if objects_to_delete:
                s3_client.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': objects_to_delete}
                )
                logger.info(f"Deleted {len(objects_to_delete)} old files from bucket {bucket_name}")
            else:
                logger.info("No old files to delete")
        else:
            logger.info("No objects found in bucket")
        
        return {
            'statusCode': 200,
            'body': {
                'message': 'Bucket cleanup completed successfully',
                'bucket': bucket_name
            }
        }
        
    except Exception as e:
        logger.error(f"Error during bucket cleanup: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': f'Error during bucket cleanup: {str(e)}'
        }