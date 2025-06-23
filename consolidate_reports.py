#!/usr/bin/env python3
import boto3
import json
import re
import os
from datetime import datetime
from bs4 import BeautifulSoup

s3 = boto3.client('s3')
bucket = os.environ['BUCKET_REPORT']

# List all account folders
response = s3.list_objects_v2(Bucket=bucket, Delimiter='/')
accounts = []
for prefix in response.get('CommonPrefixes', []):
    folder = prefix['Prefix'].rstrip('/')
    if folder.isdigit():  # Account ID folders
        accounts.append(folder)

print(f'Found account folders: {accounts}')

# Consolidate HTML results
all_rows = []
for account in accounts:
    try:
        # Get latest HTML report for this account
        objects = s3.list_objects_v2(Bucket=bucket, Prefix=f'{account}/security_assessment_')
        if 'Contents' in objects:
            html_files = [obj for obj in objects['Contents'] if obj['Key'].endswith('.html')]
            if html_files:
                latest = max(html_files, key=lambda x: x['LastModified'])
                obj = s3.get_object(Bucket=bucket, Key=latest['Key'])
                html_content = obj['Body'].read().decode('utf-8')
                
                # Parse HTML and extract table rows
                soup = BeautifulSoup(html_content, 'html.parser')
                tbody = soup.find('tbody')
                if tbody:
                    rows = tbody.find_all('tr')
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 7:  # Valid data row
                            all_rows.append(str(row))
    except Exception as e:
        print(f'Error processing account {account}: {e}')

# Generate consolidated HTML report
if all_rows:
    html_template = '''<!DOCTYPE html>
<html>
<head>
    <title>ReSCO AI/ML Multi-Account Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; white-space: nowrap; padding-bottom: 8px !important; }}
        th .header-content {{ margin-bottom: 8px; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .table-controls {{ margin: 20px 0; }}
        .column-filter {{ width: 95%; padding: 4px; margin-top: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 0.9em; }}
        #searchInput {{ width: 300px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 10px; }}
        .severity-high {{ color: #d73a4a; font-weight: bold; }}
        .severity-medium {{ color: #fb8c00; font-weight: bold; }}
        .severity-low {{ color: #2986cc; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>ReSCO AI/ML Multi-Account Security Assessment Report</h1>
    <div class="table-controls">
        <input type="text" id="searchInput" placeholder="Quick search across all columns...">
    </div>
    <table id="assessmentTable">
        <thead>
            <tr>
                <th><div class="header-content">Account ID</div><input type="text" class="column-filter" placeholder="Filter Account ID..."></th>
                <th><div class="header-content">Finding</div><input type="text" class="column-filter" placeholder="Filter Findings..."></th>
                <th><div class="header-content">Finding Details</div><input type="text" class="column-filter" placeholder="Filter Details..."></th>
                <th><div class="header-content">Resolution</div><input type="text" class="column-filter" placeholder="Filter Resolutions..."></th>
                <th><div class="header-content">Reference</div><input type="text" class="column-filter" placeholder="Filter References..."></th>
                <th><div class="header-content">Severity</div><input type="text" class="column-filter" placeholder="Filter Severity..."></th>
                <th><div class="header-content">Status</div><input type="text" class="column-filter" placeholder="Filter Status..."></th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const table = document.querySelector('table');
            const searchInput = document.getElementById('searchInput');
            const filters = document.querySelectorAll('.column-filter');
            searchInput.addEventListener('input', function() {{
                const searchText = this.value.toLowerCase();
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {{
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchText) ? '' : 'none';
                }});
            }});
            filters.forEach((filter, index) => {{
                filter.addEventListener('input', () => {{
                    const filterValues = Array.from(filters).map(f => f.value.toLowerCase());
                    const rows = table.querySelectorAll('tbody tr');
                    rows.forEach(row => {{
                        const cells = row.querySelectorAll('td');
                        let shouldShow = true;
                        filterValues.forEach((value, i) => {{
                            if (value && !cells[i].textContent.toLowerCase().includes(value)) {{
                                shouldShow = false;
                            }}
                        }});
                        row.style.display = shouldShow ? '' : 'none';
                    }});
                }});
            }});
        }});
    </script>
</body>
</html>'''
    
    consolidated_html = html_template.format(rows='\n'.join(all_rows))
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    consolidated_key = f'consolidated_report_{timestamp}.html'
    s3.put_object(
        Bucket=bucket,
        Key=consolidated_key,
        Body=consolidated_html,
        ContentType='text/html'
    )
    print(f'Consolidated HTML report saved: s3://{bucket}/{consolidated_key}')
else:
    print('No results found to consolidate')