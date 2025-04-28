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
        base_path = f"{execution_id}"
        
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


def generate_html_report(assessment_results: Dict[str, Any]) -> str:
    """
    Generate HTML report from assessment results with sortable, filterable table and pagination
    
    Args:
        assessment_results (Dict[str, Any]): Assessment results from get_assessment_results
    
    Returns:
        str: HTML content as string
    """

    # Calculate metrics
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    finding_counts = {}
    
    # Process Bedrock findings
    for findings in assessment_results.get('bedrock', {}).values():
        for finding in findings:
            severity = finding.get('Severity', 'Low')
            finding_name = finding.get('Finding', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            finding_counts[finding_name] = finding_counts.get(finding_name, 0) + 1
    
    # Process SageMaker findings
    for findings in assessment_results.get('sagemaker', {}).values():
        for finding in findings:
            severity = finding.get('Severity', 'Low')
            finding_name = finding.get('Finding', 'Unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            finding_counts[finding_name] = finding_counts.get(finding_name, 0) + 1

    html_template = r"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AIML Security Assessment Report</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                color: #333;
            }}
            .header {{
                margin-bottom: 20px;
            }}
            .summary {{
                margin-bottom: 30px;
                padding: 15px;
                background-color: #f8f9fa;
                border-radius: 5px;
            }}
            .severity-high {{
                color: #dc3545;
                font-weight: bold;
            }}
            .severity-medium {{
                color: #ffc107;
                font-weight: bold;
            }}
            .severity-low {{
                color: #28a745;
                font-weight: bold;
            }}
            .status-failed {{
                color: #dc3545;
            }}
            .status-passed {{
                color: #28a745;
            }}
            .timestamp {{
                color: #666;
                font-size: 0.9em;
            }}
            .dataTables_filter {{
                margin-bottom: 10px;
            }}
            .resolution-link {{
                color: #0d6efd;
                text-decoration: none;
            }}
            .resolution-link:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="container-fluid">
            <div class="header">
                <h1>AIML Security Assessment Report</h1>
                <p class="timestamp">Generated: {timestamp}</p>
                <p>Execution ID: {execution_id}</p>
            </div>
            <h2>Findings</h2>
            <table id="findingsTable" class="table table-striped table-bordered">
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
                    {table_rows}
                </tbody>
            </table>
        </div>

        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
        <script>
            $(document).ready(function() {{
                $('#findingsTable').DataTable({{
                    pageLength: 10,
                    lengthMenu: [[10, 20, 50, -1], [10, 20, 50, "All"]],
                    order: [[4, 'desc']], // Sort by Severity by default
                    columnDefs: [
                        {{
                            targets: 2, // Resolution column
                            render: function(data, type, row) {{
                                if (type === 'display' && data) {{
                                    // Split multiple URLs and create links
                                    const urls = data.split('\\n').map(line => {{
                                        const urlMatch = line.match(/(https?:\/\/[^\s]+)/g);
                                        if (urlMatch) {{
                                            return line.replace(urlMatch[0], 
                                                `<a href="${{urlMatch[0]}}" class="resolution-link" target="_blank">${{urlMatch[0]}}</a>`);
                                        }}
                                        return line;
                                    }});
                                    return urls.join('<br>');
                                }}
                                return data;
                            }}
                        }},
                        {{
                            targets: 3, // Reference column
                            render: function(data, type, row) {{
                                if (type === 'display' && data) {{
                                    // Split multiple URLs and create links
                                    const urls = data.split('\\n').map(url => 
                                        `<a href="${{url}}" class="resolution-link" target="_blank">${{url}}</a>`);
                                    return urls.join('<br>');
                                }}
                                return data;
                            }}
                        }},
                        {{
                            targets: 4, // Severity column
                            render: function(data, type, row) {{
                                if (type === 'display') {{
                                    const severityClass = data.toLowerCase() === 'high' ? 'severity-high' :
                                                        data.toLowerCase() === 'medium' ? 'severity-medium' :
                                                        'severity-low';
                                    return `<span class="${{severityClass}}">${{data}}</span>`;
                                }}
                                return data;
                            }}
                        }},
                        {{
                            targets: 5, // Status column
                            render: function(data, type, row) {{
                                if (type === 'display') {{
                                    const statusClass = data.toLowerCase() === 'failed' ? 'status-failed' : 'status-passed';
                                    return `<span class="${{statusClass}}">${{data}}</span>`;
                                }}
                                return data;
                            }}
                        }}
                    ]
                }});
            }});
        </script>
    </body>
    </html>
    """

    # Generate table rows from assessment results
    rows = []
    for assessment_type, findings in assessment_results.get('bedrock', {}).items():
        for finding in findings:
            row = f"""
                <tr>
                    <td>Bedrock - {finding.get('Finding', 'N/A')}</td>
                    <td>{finding.get('Finding_Details', 'N/A')}</td>
                    <td>{finding.get('Resolution', 'N/A')}</td>
                    <td>{finding.get('Reference', 'N/A')}</td>
                    <td>{finding.get('Severity', 'Low')}</td>
                    <td>{finding.get('Status', 'Open')}</td>
                </tr>
            """
            rows.append(row)
    
    for assessment_type, findings in assessment_results.get('sagemaker', {}).items():
        for finding in findings:
            row = f"""
                <tr>
                    <td>SageMaker - {finding.get('Finding', 'N/A')}</td>
                    <td>{finding.get('Finding_Details', 'N/A')}</td>
                    <td>{finding.get('Resolution', 'N/A')}</td>
                    <td>{finding.get('Reference', 'N/A')}</td>
                    <td>{finding.get('Severity', 'Low')}</td>
                    <td>{finding.get('Status', 'Open')}</td>
                </tr>
            """
            rows.append(row)

    # Generate the HTML content
    html_content = html_template.format(
        timestamp=assessment_results.get('timestamp', 'N/A'),
        execution_id=assessment_results.get('execution_id', 'N/A'),
        total_files=assessment_results.get('summary', {}).get('total_files_processed', 0),
        categories=', '.join(assessment_results.get('summary', {}).get('categories_found', [])),
        table_rows='\n'.join(rows),
        high_count=severity_counts.get('High', 0),
        medium_count=severity_counts.get('Medium', 0),
        low_count=severity_counts.get('Low', 0),
        info_count=severity_counts.get('Informational', 0)
    )

    
    return html_content

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
        s3_key = f'{execution_id}/security_assessment.html'
        
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