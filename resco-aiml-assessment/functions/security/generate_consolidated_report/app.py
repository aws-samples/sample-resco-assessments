import boto3
import csv
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from io import StringIO
from botocore.config import Config
from botocore.exceptions import ClientError

boto3_config = Config(
    retries = dict(
        max_attempts = 10,  # Maximum number of retries
        mode = 'adaptive'  # Exponential backoff with adaptive mode
    )
)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

def parse_csv_content(csv_content: str) -> List[Dict[str, str]]:
    """
    Parse CSV content into a list of dictionaries
    
    Args:
        csv_content (str): CSV content as string
    
    Returns:
        List[Dict[str, str]]: List of dictionaries where each dict represents a row
    """
    results = []
    csv_file = StringIO(csv_content)
    csv_reader = csv.DictReader(csv_file)
    
    for row in csv_reader:
        results.append(dict(row))
    
    return results

def get_assessment_results(execution_id: str) -> Dict[str, Any]:
    """
    Download and parse Bedrock and SageMaker assessment CSV files for a given execution
    
    Args:
        s3_bucket (str): Source S3 bucket name
        execution_id (str): Step Functions execution ID
    
    Returns:
        Dict[str, Any]: Nested object containing all assessment results
    """
    try:
        s3_client = boto3.client('s3', config=boto3_config)
        
        # Define the base path for this execution
        date_string = get_current_utc_date()
        base_path = f"{date_string}/{execution_id}"
        
        # List all CSV files in the execution directory
        s3_bucket = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')
        response = s3_client.list_objects_v2(
            Bucket=s3_bucket,
            Prefix=base_path
        )
        
        if 'Contents' not in response:
            logger.warning(f"No assessment files found for execution {execution_id}")
            return {}

        assessment_results = {
            'execution_id': execution_id,
            'timestamp': datetime.now().isoformat(),
            'bedrock': {},
            'sagemaker': {}
        }

        # Process each CSV file
        for obj in response['Contents']:
            s3_key = obj['Key']
            
            # Skip if not a CSV file
            if not s3_key.endswith('.csv'):
                continue
                
            try:
                # Get the file content
                response = s3_client.get_object(
                    Bucket=s3_bucket,
                    Key=s3_key
                )
                
                # Read CSV content
                csv_content = response['Body'].read().decode('utf-8')
                
                # Parse CSV content
                parsed_data = parse_csv_content(csv_content)
                
                # Determine which category this file belongs to based on the path
                file_name = os.path.basename(s3_key)
                category = None
                
                if 'bedrock' in s3_key.lower():
                    category = 'bedrock'
                elif 'sagemaker' in s3_key.lower():
                    category = 'sagemaker'
                else:
                    logger.warning(f"Unknown assessment type for file: {s3_key}")
                    continue
                
                # Store parsed data in appropriate category
                assessment_type = file_name.replace('.csv', '').lower()
                assessment_results[category][assessment_type] = parsed_data
                
                logger.info(f"Successfully processed {file_name} for {category} assessment")
                
            except Exception as e:
                logger.error(f"Error processing file {s3_key}: {str(e)}", exc_info=True)
                continue
        
        # Add summary information
        assessment_results['summary'] = {
            'total_files_processed': len(assessment_results['bedrock']) + 
                                   len(assessment_results['sagemaker']),
            'categories_found': [
                cat for cat in ['bedrock', 'sagemaker'] 
                if assessment_results[cat]
            ],
            'rows': assessment_results['bedrock'],
            'assessment_types': {
                'bedrock': list(assessment_results['bedrock'].keys()),
                'sagemaker': list(assessment_results['sagemaker'].keys())
            }
        }
        
        return assessment_results
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            logger.error(f"Bucket not found: {s3_bucket}")
        else:
            logger.error(f"AWS error retrieving assessment results: {str(e)}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error retrieving assessment results: {str(e)}", exc_info=True)
        raise


def generate_html_report(assessment_results):
    """
    Generate HTML report from assessment results
    """
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReSCO AI/ML Security Assessment Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #f2f2f2; position: relative; padding-bottom: 30px !important; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .table-controls { margin: 20px 0; }
            .column-filter {
                width: 95%;
                padding: 5px;
                margin-bottom: 5px;
                border: 1px solid #ddd;
                border-radius: 4px;
                position: absolute;
                bottom: 5px;
                left: 0;
            }
            #searchInput {
                width: 300px;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin-bottom: 10px;
            }
            .severity-high { color: #d73a4a; font-weight: bold; }
            .severity-medium { color: #fb8c00; font-weight: bold; }
            .severity-low { color: #2986cc; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>ReSCO AI/ML Security Assessment Report</h1>
        <div class="table-controls">
            <input type="text" id="searchInput" placeholder="Quick search across all columns...">
        </div>
        <table id="assessmentTable">
            <thead>
                <tr>
                    <th>Finding</th>
                    <th>Finding Details</th>
                    <th>Resolution</th>
                    <th>Reference</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const table = document.querySelector('table');
            const headers = table.querySelectorAll('th');
            
            // Add filter input to each column header
            headers.forEach((header, index) => {
                const input = document.createElement('input');
                input.className = 'column-filter';
                input.placeholder = `Filter ${header.textContent}...`;
                input.addEventListener('input', () => filterColumn(index));
                header.appendChild(input);
            });

            // Global search functionality
            document.getElementById('searchInput').addEventListener('input', function() {
                const searchText = this.value.toLowerCase();
                const rows = table.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchText) ? '' : 'none';
                });
            });

            function filterColumn(column) {
                const filters = Array.from(document.querySelectorAll('.column-filter'))
                    .map(input => input.value.toLowerCase());
                
                const rows = table.querySelectorAll('tbody tr');
                
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    let shouldShow = true;
                    
                    filters.forEach((filter, index) => {
                        if (filter && !cells[index].textContent.toLowerCase().includes(filter)) {
                            shouldShow = false;
                        }
                    });
                    
                    row.style.display = shouldShow ? '' : 'none';
                });
            }
        });
        </script>
    </body>
    </html>
    """

    # Generate table rows from assessment results
    rows = []
    for result in assessment_results:
        for finding in result.get('body', {}).get('findings', []):
            for data in finding.get('csv_data', []):
                severity_class = f"severity-{data['Severity'].lower()}" if 'Severity' in data else ""
                row = f"""
                <tr>
                    <td>{data.get('Finding', '')}</td>
                    <td>{data.get('Finding_Details', '')}</td>
                    <td>{data.get('Resolution', '')}</td>
                    <td><a href="{data.get('Reference', '')}" target="_blank">{data.get('Reference', '')}</a></td>
                    <td class="{severity_class}">{data.get('Severity', '')}</td>
                    <td>{data.get('Status', '')}</td>
                </tr>
                """
                rows.append(row)

    # Replace {rows} placeholder with generated rows
    html_content = html_template.format(rows='\n'.join(rows))
    
    return html_content



def get_current_utc_date():
    return datetime.utcnow().strftime("%Y/%m/%d")

def write_html_to_s3(html_content: str, s3_bucket: str, execution_id: str) -> Optional[str]:
    """
    Write HTML report to S3
    
    Args:
        html_content (str): HTML content to write
        s3_bucket (str): Destination S3 bucket name
        execution_id (str): Step Functions execution ID
    
    Returns:
        Optional[str]: S3 key if successful, None if error
    """
    try:
        s3_client = boto3.client('s3', config=boto3_config)
        
        # Generate the S3 key
        date_string = get_current_utc_date()
        s3_key = f'{date_string}/{execution_id}/security_assessment.html'
        
        # Upload the HTML file
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=html_content,
            ContentType='text/html',
            Metadata={
                'execution-id': execution_id
            }
        )
        
        logger.info(f"Successfully wrote HTML report to s3://{s3_bucket}/{s3_key}")
        return s3_key
        
    except Exception as e:
        logger.error(f"Error writing HTML report to S3: {str(e)}", exc_info=True)
        return None

def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Generating Consolidated HTML Report")
    logger.info(f"Event: {event}")
    
    try:
        # Get execution ID from event
        execution_id = event["Execution"]["Name"]
        print(execution_id)
        # Get S3 bucket name from environment variable
        s3_bucket = os.environ.get('AIML_ASSESSMENT_BUCKET_NAME')
        if not s3_bucket:
            raise ValueError("AIML_ASSESSMENT_BUCKET_NAME environment variable is required")
        
        # Get assessment results
        assessment_results = get_assessment_results(execution_id)
        
        if not assessment_results:
            raise ValueError(f"No assessment results found: {execution_id}")
        
        # Generate HTML report
        html_content = generate_html_report(assessment_results)
        
        # Write HTML report to S3
        s3_key = write_html_to_s3(html_content, s3_bucket, execution_id)
        
        if not s3_key:
            raise Exception("Failed to write HTML report to S3")
        
        return {
            'statusCode': 200,
            'executionId': execution_id,
            'body': {
                'message': 'Successfully generated HTML report',
                'report_location': f"s3://{s3_bucket}/{s3_key}",
            }
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'executionId': execution_id if 'execution_id' in locals() else 'unknown',
            'body': f'Error generating HTML report: {str(e)}'
        }