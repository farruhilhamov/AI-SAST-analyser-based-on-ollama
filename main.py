import os
import json
import requests
from pathlib import Path
import time
import logging
import argparse
import re
from typing import List, Dict, Any, Tuple
import concurrent.futures

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("sast_analyzer.log")
    ]
)
logger = logging.getLogger("PerplexitySASTAnalyzer")

class PerplexitySASTAnalyzer:
    def __init__(self, api_key: str, path: str, output_dir: str = None, 
                 exclude_dirs: List[str] = None, max_files_per_batch: int = 4):
        """
        Initialize the SAST analyzer with API key and path to scan.
        
        Args:
            api_key: Perplexity API key
            path: Path to scan for code files
            output_dir: Directory to save output reports
            exclude_dirs: List of directories to exclude from scanning
            max_files_per_batch: Maximum number of files to send in one API request
        """
        self.api_key = api_key
        self.path = Path(path)
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "sast_reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.exclude_dirs = exclude_dirs or ['.git', 'node_modules', 'venv', '__pycache__']
        self.max_files_per_batch = max_files_per_batch
        
        # Common code file extensions
        self.code_extensions = {
            '.py', '.js', '.java', '.c', '.cpp', '.cs', '.go', '.rb', 
            '.php', '.html', '.css', '.ts', '.swift', '.kt', '.rs',
            '.sh', '.ps1', '.sql', '.yaml', '.yml', '.json', '.xml',
            '.jsx', '.tsx', '.vue', '.scala', '.groovy'
        }
        
        # Maximum file size for analysis (25MB as per Perplexity limits)
        self.max_file_size = 25 * 1024 * 1024
        
        # Timestamp for this run
        self.timestamp = time.strftime("%Y%m%d-%H%M%S")
        
    def get_code_files(self) -> List[Path]:
        """Get all code files in the specified path."""
        code_files = []
        
        for file_path in self.path.rglob('*'):
            # Skip excluded directories
            if any(excluded in file_path.parts for excluded in self.exclude_dirs):
                continue
                
            if file_path.is_file() and file_path.suffix.lower() in self.code_extensions:
                # Check if file size is within limits
                if file_path.stat().st_size <= self.max_file_size:
                    code_files.append(file_path)
                else:
                    logger.warning(f"Skipping {file_path} as it exceeds the maximum file size of 25MB.")
        
        return code_files
    
    def group_files(self, code_files: List[Path]) -> List[List[Path]]:
        """Group files optimally for sending to the API."""
        # Group files by directory to keep related files together
        files_by_dir = {}
        for file_path in code_files:
            dir_path = str(file_path.parent)
            if dir_path not in files_by_dir:
                files_by_dir[dir_path] = []
            files_by_dir[dir_path].append(file_path)
        
        # Create batches while trying to keep files from the same directory together
        batches = []
        current_batch = []
        
        for dir_path, dir_files in files_by_dir.items():
            for file_path in dir_files:
                if len(current_batch) >= self.max_files_per_batch:
                    batches.append(current_batch)
                    current_batch = []
                current_batch.append(file_path)
        
        # Add the last batch if it's not empty
        if current_batch:
            batches.append(current_batch)
        
        return batches
    
    def analyze_files(self, file_group: List[Path]) -> Dict[str, Any]:
        """Send files to Perplexity API for vulnerability analysis."""
        url = "https://api.perplexity.ai/chat/completions"
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # Prepare files for analysis
        files_content = {}
        for file_path in file_group:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    files_content[str(file_path)] = content
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
        
        # Create the prompt with files content
        prompt = self._create_prompt(files_content)
        
        # Prepare the payload
        payload = {
            "model": "sonar-pro",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a SAST (Static Application Security Testing) analyzer. Analyze the provided code files for security vulnerabilities, including but not limited to: injection flaws, broken authentication, sensitive data exposure, XML external entities, broken access control, security misconfiguration, cross-site scripting, insecure deserialization, using components with known vulnerabilities, and insufficient logging & monitoring."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        # Make the API request
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error making API request: {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response text: {e.response.text}")
            return {"error": str(e)}
    
    def _create_prompt(self, files_content: Dict[str, str]) -> str:
        """Create an optimized prompt for the Perplexity API."""
        prompt = """
        Please analyze the following code files for security vulnerabilities. For each vulnerability found, provide detailed information in a JSON format.
        
        Files to analyze:
        """
        
        for file_path, content in files_content.items():
            prompt += f"\n===== FILE: {file_path} =====\n``````\n"
        
        prompt += """
        For each vulnerability found, please provide:
        1. Vulnerability name and type (e.g., SQL Injection, XSS)
        2. Severity (Critical, High, Medium, Low, Note)
        3. File path
        4. Line number(s)
        5. Brief description of the vulnerability
        6. Code snippet showing the vulnerable code
        7. Recommendation for remediation
        8. CWE ID if applicable
        
        Please respond in a structured JSON format like:
        {
            "vulnerabilities": [
                {
                    "name": "Vulnerability name",
                    "type": "Vulnerability type",
                    "severity": "Critical/High/Medium/Low/Note",
                    "file": "file_path",
                    "line_numbers": [123, 124],
                    "description": "Description of the vulnerability",
                    "code_snippet": "Vulnerable code",
                    "remediation": "How to fix it",
                    "cwe_id": "CWE-123"
                }
            ],
            "summary": {
                "total_files_analyzed": 3,
                "total_vulnerabilities": 5,
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
                "note": 0
            }
        }
        """
        
        return prompt
    
    def parse_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the API response to extract vulnerability information."""
        try:
            # Extract content from the API response
            if 'choices' in response and len(response['choices']) > 0:
                content = response['choices'][0]['message']['content']
                
                try:
                    # Try to parse directly first
                    json_data = json.loads(content)
                    return json_data
                except json.JSONDecodeError:
                    # If that fails, try to extract JSON from the text
                    json_match = re.search(r'``````', content, re.DOTALL)
                    if json_match:
                        try:
                            json_str = json_match.group(1)
                            return json.loads(json_str)
                        except json.JSONDecodeError:
                            pass
                    
                    # If all fails, return an error
                    return {
                        "error": "Could not parse JSON from API response",
                        "raw_content": content
                    }
            else:
                return {"error": "No content in API response"}
        except Exception as e:
            return {"error": f"Error parsing API response: {e}"}
    
    def generate_report(self, analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a comprehensive SAST report from multiple analysis results."""
        consolidated_vulnerabilities = []
        total_files_analyzed = 0
        
        # Counters for summary
        summary = {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "note": 0
        }
        
        # Process each analysis result
        for result in analysis_results:
            if "error" in result:
                continue
            
            if "vulnerabilities" in result:
                consolidated_vulnerabilities.extend(result["vulnerabilities"])
                
                # Update counters
                summary["total_vulnerabilities"] += len(result["vulnerabilities"])
                
                for vuln in result["vulnerabilities"]:
                    severity = vuln.get("severity", "").lower()
                    if severity in summary:
                        summary[severity] += 1
            
            if "summary" in result and "total_files_analyzed" in result["summary"]:
                total_files_analyzed += result["summary"]["total_files_analyzed"]
        
        # Create the consolidated report
        consolidated_report = {
            "vulnerabilities": consolidated_vulnerabilities,
            "summary": {
                "total_files_analyzed": total_files_analyzed,
                **summary
            },
            "scan_timestamp": self.timestamp
        }
        
        return consolidated_report
    
    def save_report(self, report: Dict[str, Any], format_type: str = "json") -> str:
        """Save the report to a file in the specified format."""
        if format_type == "json":
            report_path = self.output_dir / f"sast_report_{self.timestamp}.json"
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
        elif format_type == "html":
            report_path = self.output_dir / f"sast_report_{self.timestamp}.html"
            html_content = self._generate_html_report(report)
            with open(report_path, 'w') as f:
                f.write(html_content)
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
        
        return str(report_path)
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate an HTML report from the analysis results."""
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SAST Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                h2 {{ color: #3498db; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .vulnerability {{ background-color: #fff; padding: 15px; margin-bottom: 15px; border-left: 5px solid #3498db; }}
                .critical {{ border-color: #e74c3c; }}
                .high {{ border-color: #e67e22; }}
                .medium {{ border-color: #f1c40f; }}
                .low {{ border-color: #2ecc71; }}
                .note {{ border-color: #95a5a6; }}
                pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #3498db; color: white; }}
            </style>
        </head>
        <body>
            <h1>SAST Analysis Report</h1>
            <p>Generated on: {timestamp}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <table>
                    <tr>
                        <th>Metric</th>
                        <th>Count</th>
                    </tr>
                    <tr>
                        <td>Total Files Analyzed</td>
                        <td>{total_files_analyzed}</td>
                    </tr>
                    <tr>
                        <td>Total Vulnerabilities</td>
                        <td>{total_vulnerabilities}</td>
                    </tr>
                    <tr>
                        <td>Critical</td>
                        <td>{critical}</td>
                    </tr>
                    <tr>
                        <td>High</td>
                        <td>{high}</td>
                    </tr>
                    <tr>
                        <td>Medium</td>
                        <td>{medium}</td>
                    </tr>
                    <tr>
                        <td>Low</td>
                        <td>{low}</td>
                    </tr>
                    <tr>
                        <td>Note</td>
                        <td>{note}</td>
                    </tr>
                </table>
            </div>
            
            <h2>Vulnerabilities</h2>
        """.format(timestamp=time.strftime("%Y-%m-%d %H:%M:%S"), **report["summary"])
        
        # Add each vulnerability
        for vuln in report["vulnerabilities"]:
            severity_class = vuln.get("severity", "").lower()
            
            html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.get("name", "Unnamed Vulnerability")}</h3>
                <p><strong>Type:</strong> {vuln.get("type", "Unknown")}</p>
                <p><strong>Severity:</strong> {vuln.get("severity", "Unknown")}</p>
                <p><strong>File:</strong> {vuln.get("file", "Unknown")}</p>
                <p><strong>Line Numbers:</strong> {', '.join(map(str, vuln.get("line_numbers", [])))}</p>
                <p><strong>Description:</strong> {vuln.get("description", "No description")}</p>
                <p><strong>Code Snippet:</strong></p>
                <pre><code>{vuln.get("code_snippet", "No code snippet")}</code></pre>
                <p><strong>Remediation:</strong> {vuln.get("remediation", "No remediation suggestion")}</p>
            </div>"""
        
            html += """
            </body>
            </html>
            """
        
        return html


    
    def run(self) -> Tuple[Dict[str, Any], str]:
        """Run the SAST analysis and generate reports."""
        # Get all code files
        code_files = self.get_code_files()
        logger.info(f"Found {len(code_files)} code files to analyze.")
        
        # Group files for analysis
        file_groups = self.group_files(code_files)
        logger.info(f"Grouped files into {len(file_groups)} batches for analysis.")
        
        # Analyze each group of files
        analysis_results = []
        for i, file_group in enumerate(file_groups):
            logger.info(f"Analyzing batch {i+1}/{len(file_groups)} ({len(file_group)} files)...")
            response = self.analyze_files(file_group)
            parsed_response = self.parse_response(response)
            analysis_results.append(parsed_response)
            
            # Be nice to the API - add a small delay between requests
            if i < len(file_groups) - 1:
                time.sleep(1)
        
        # Generate the consolidated report
        report = self.generate_report(analysis_results)
        
        # Save the report in different formats
        html_path = self.save_report(report, "html")
        logger.info(f"HTML report saved to {html_path}")
        
        json_path = self.save_report(report, "json")
        logger.info(f"JSON report saved to {json_path}")
        
        logger.info("SAST analysis complete.")
        
        return report, html_path

def main():
    """Main function to run the SAST analyzer."""
    parser = argparse.ArgumentParser(description='SAST analyzer using Perplexity API')
    parser.add_argument('--api-key', required=True, help='Perplexity API key')
    parser.add_argument('--path', required=True, help='Path to scan for code files')
    parser.add_argument('--output-dir', help='Directory to save output reports')
    parser.add_argument('--exclude-dirs', nargs='+', help='Directories to exclude from scanning')
    
    args = parser.parse_args()
    
    analyzer = PerplexitySASTAnalyzer(
        api_key=args.api_key,
        path=args.path,
        output_dir=args.output_dir,
        exclude_dirs=args.exclude_dirs
    )
    
    analyzer.run()

if __name__ == "__main__":
    main()
