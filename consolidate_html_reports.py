#!/usr/bin/env python3
import os
import glob
import boto3
from bs4 import BeautifulSoup
from datetime import datetime

def consolidate_html_reports():
    """Consolidate HTML reports from all accounts into a single report"""
    
    s3 = boto3.client('s3')
    bucket = os.environ['BUCKET_REPORT']
    
    all_rows = []
    
    # Process HTML files from each account directory
    for account_dir in glob.glob('/tmp/account-files/*/'):
        account_id = os.path.basename(account_dir.rstrip('/'))
        html_files = glob.glob(os.path.join(account_dir, '*.html'))
        
        if html_files:
            print(f"Processing HTML files for account {account_id}")
            # Process the first HTML file found
            with open(html_files[0], 'r') as f:
                soup = BeautifulSoup(f.read(), 'html.parser')
                tbody = soup.find('tbody')
                if tbody:
                    rows = tbody.find_all('tr')
                    for row in rows:
                        # Add account ID as first cell
                        cells = row.find_all('td')
                        if cells and not cells[0].get_text().strip() == account_id:
                            account_cell = soup.new_tag('td')
                            account_cell.string = account_id
                            row.insert(0, account_cell)
                        all_rows.append(str(row))
    
    if all_rows:
        html_template = '''<!DOCTYPE html>
<html><head><title>Multi-Account ReSCO AI/ML Security Assessment Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:20px}}
table{{border-collapse:collapse;width:100%;margin-top:20px}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background-color:#f2f2f2}}
tr:nth-child(even){{background-color:#f9f9f9}}
.severity-high{{color:#d73a4a;font-weight:bold}}
.severity-medium{{color:#fb8c00;font-weight:bold}}
.severity-low{{color:#2986cc;font-weight:bold}}
</style></head>
<body>
<h1>Multi-Account ReSCO AI/ML Security Assessment Report</h1>
<p>Generated: {timestamp}</p>
<table>
<thead><tr><th>Account ID</th><th>Finding</th><th>Finding Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>'''
        
        consolidated_html = html_template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            rows=''.join(all_rows)
        )
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        s3.put_object(
            Bucket=bucket,
            Key=f'consolidated-reports/multi_account_report_{timestamp}.html',
            Body=consolidated_html,
            ContentType='text/html'
        )
        print(f'Consolidated report saved to s3://{bucket}/consolidated-reports/multi_account_report_{timestamp}.html')
    else:
        print('No HTML reports found for consolidation')

if __name__ == '__main__':
    consolidate_html_reports()