# test_generate_report.py
import unittest
import os
import webbrowser
from app import generate_html_report

class TestHtmlReportGeneration(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_reports"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)
            
        self.test_assessment_results = [{
            "body": {
                "findings": [{
                    "csv_data": [
                        {
                            "Finding": "Bedrock Model Access Control",
                            "Finding_Details": "The Bedrock model access is not restricted to specific IAM principals. This could allow unauthorized access to model endpoints.",
                            "Resolution": "Implement IAM policies to restrict access to specific principals and use resource-based policies for model invocations.",
                            "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                            "Severity": "High",
                            "Status": "Open"
                        },
                        {
                            "Finding": "Bedrock API Logging",
                            "Finding_Details": "CloudTrail logging is not enabled for Bedrock API calls. This limits audit capabilities and incident investigation.",
                            "Resolution": "Enable CloudTrail logging for Bedrock API actions and configure log retention policies.",
                            "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                            "Severity": "Medium",
                            "Status": "Open"
                        }
                    ]
                }]
            }
        },
        {
            "body": {
                "findings": [{
                    "csv_data": [
                        {
                            "Finding": "SageMaker Endpoint Encryption",
                            "Finding_Details": "SageMaker endpoint is not using encryption at rest. Sensitive data could be exposed if storage is compromised.",
                            "Resolution": "Enable AWS KMS encryption for SageMaker endpoints using customer managed keys.",
                            "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                            "Severity": "High",
                            "Status": "Open"
                        },
                        {
                            "Finding": "SageMaker Network Isolation",
                            "Finding_Details": "SageMaker training jobs are not configured with network isolation. This could expose the training environment to external networks.",
                            "Resolution": "Enable network isolation for SageMaker training jobs and use VPC configurations.",
                            "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                            "Severity": "Medium",
                            "Status": "In Progress"
                        },
                        {
                            "Finding": "SageMaker IAM Role Permissions",
                            "Finding_Details": "SageMaker execution role has overly permissive IAM policies. This violates the principle of least privilege.",
                            "Resolution": "Review and restrict IAM role permissions to only necessary actions and resources.",
                            "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html",
                            "Severity": "High",
                            "Status": "Open"
                        }
                    ]
                }]
            }
        }]

    def test_generate_viewable_report(self):
        """Generate a viewable HTML report with test data"""
        html_content = generate_html_report(self.test_assessment_results)
        
        # Save the HTML content to a file
        report_path = os.path.join(self.test_dir, "security_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)
        
        print(f"\nReport generated at: {os.path.abspath(report_path)}")
        
        # Optionally open the report in the default browser
        webbrowser.open('file://' + os.path.abspath(report_path))
        
        # Verify file exists and has content
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.getsize(report_path) > 0)
        
        # Basic content checks
        with open(report_path, 'r') as f:
            content = f.read()
            # Bedrock findings
            self.assertIn("Bedrock Model Access Control", content)
            self.assertIn("Bedrock API Logging", content)
            
            # SageMaker findings
            self.assertIn("SageMaker Endpoint Encryption", content)
            self.assertIn("SageMaker Network Isolation", content)
            self.assertIn("SageMaker IAM Role Permissions", content)
            
            # Severity levels
            self.assertIn("High", content)
            self.assertIn("Medium", content)

    def test_missing_data_fields(self):
        """Test handling of assessment results with missing fields"""
        incomplete_data = [{
            "body": {
                "findings": [{
                    "csv_data": [{
                        "Finding": "Incomplete Bedrock Finding",
                        "Severity": "High"
                        # Missing other fields
                    }]
                }]
            }
        }]
        
        html_content = generate_html_report(incomplete_data)
        
        # Save the HTML content to a file
        report_path = os.path.join(self.test_dir, "incomplete_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)
            
        print(f"\nIncomplete data report generated at: {os.path.abspath(report_path)}")
        
        # Verify file exists and has content
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.getsize(report_path) > 0)

    def test_empty_findings(self):
        """Test handling of empty findings"""
        empty_data = [{
            "body": {
                "findings": [{
                    "csv_data": []
                }]
            }
        }]
        
        html_content = generate_html_report(empty_data)
        report_path = os.path.join(self.test_dir, "empty_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)
            
        print(f"\nEmpty data report generated at: {os.path.abspath(report_path)}")
        self.assertTrue(os.path.exists(report_path))

    def tearDown(self):
        """Clean up test files after running tests"""
        # Optionally remove test files
        # Comment out these lines if you want to keep the generated reports
        # for report_file in os.listdir(self.test_dir):
        #     os.remove(os.path.join(self.test_dir, report_file))
        # os.rmdir(self.test_dir)
        pass

if __name__ == '__main__':
    unittest.main()
