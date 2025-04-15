import os
import re
import sys
import json
import argparse
import concurrent.futures
import threading  # Add this import explicitly
from pathlib import Path
import requests
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sast.log')
    ]
)
logger = logging.getLogger('sast')

# Define file types to analyze
CODE_EXTENSIONS = {
    # Programming languages
    '.py': 'Python', '.js': 'JavaScript', '.java': 'Java', '.c': 'C', '.cpp': 'C++',
    '.cs': 'C#', '.go': 'Go', '.rb': 'Ruby', '.php': 'PHP', '.swift': 'Swift',
    '.ts': 'TypeScript', '.sh': 'Shell', '.pl': 'Perl', '.kt': 'Kotlin', '.rs': 'Rust',
    
    # Configuration files
    '.yml': 'YAML', '.yaml': 'YAML', '.json': 'JSON', '.xml': 'XML', '.toml': 'TOML',
    '.ini': 'INI', '.conf': 'Config', '.env': 'Environment', '.properties': 'Properties',
    
    # Web
    '.html': 'HTML', '.css': 'CSS', '.jsx': 'React JSX', '.tsx': 'React TSX',
    
    # Infrastructure
    '.tf': 'Terraform', '.dockerfile': 'Dockerfile', 'dockerfile': 'Dockerfile', '.sql': 'SQL',
}

# Default directories to exclude
DEFAULT_EXCLUDE_DIRS = [
    'node_modules', 'venv', '.venv', '__pycache__', '.git', '.github',
    'dist', 'build', 'bin', 'obj', 'target', '.idea', '.vscode',
]

# Comment patterns by language
COMMENT_PATTERNS = {
    'Python': [
        (r'#.*?$', ''),  # Single line comments
        (r'""".*?"""', '', re.DOTALL),  # Multi-line docstrings
        (r"'''.*?'''", '', re.DOTALL),  # Multi-line docstrings with single quotes
    ],
    'JavaScript': [
        (r'//.*?$', ''),  # Single line comments
        (r'/\*.*?\*/', '', re.DOTALL),  # Multi-line comments
    ],
    'Java': [
        (r'//.*?$', ''),  # Single line comments
        (r'/\*.*?\*/', '', re.DOTALL),  # Multi-line comments
    ],
    # More languages abbreviated for brevity - you would include all from the thinking section
}

# Rate limiting implementation
class RateLimiter:
    def __init__(self, max_calls_per_minute=10):
        self.max_calls_per_minute = max_calls_per_minute
        self.calls = []
        self.lock = threading.Lock()  # Use threading.Lock directly
                
    def wait_if_needed(self):
        current_time = time.time()
        with self.lock:
            # Remove calls older than 1 minute
            self.calls = [t for t in self.calls if current_time - t < 60]
            
            # If we've reached the maximum calls within a minute, wait
            if len(self.calls) >= self.max_calls_per_minute:
                oldest_call = min(self.calls)
                sleep_time = 60 - (current_time - oldest_call)
                if sleep_time > 0:
                    logger.debug(f"Rate limiting: waiting {sleep_time:.2f} seconds")
                    time.sleep(sleep_time)
            
            # Record this call
            self.calls.append(time.time())

def remove_comments(code, language):
    """Remove comments from code based on language."""
    if language not in COMMENT_PATTERNS:
        return code  # Return original if language not supported
    
    clean_code = code
    for pattern, replacement, *flags in COMMENT_PATTERNS[language]:
        flag = flags[0] if flags else 0
        clean_code = re.sub(pattern, replacement, clean_code, flags=flag)
    
    return clean_code

def scan_directory(directory_path, exclude_dirs=None, include_extensions=None):
    """Recursively scan a directory and return list of files to analyze."""
    if exclude_dirs is None:
        exclude_dirs = DEFAULT_EXCLUDE_DIRS
    
    files_to_analyze = []
    
    for root, dirs, files in os.walk(directory_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1].lower()
            
            # Handle Dockerfile which might not have an extension
            if file.lower() == 'dockerfile':
                file_extension = 'dockerfile'
            
            # Check if we should include this file
            if include_extensions and file_extension not in include_extensions:
                continue
                
            if file_extension in CODE_EXTENSIONS:
                files_to_analyze.append({
                    'path': file_path,
                    'language': CODE_EXTENSIONS[file_extension],
                    'extension': file_extension
                })
    
    return files_to_analyze

def optimize_code(file_info):
    """Optimize code by removing comments and formatting."""
    try:
        with open(file_info['path'], 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()
        
        # Remove comments
        optimized_code = remove_comments(code, file_info['language'])
        
        # Remove extra whitespace and blank lines
        optimized_code = re.sub(r'\n\s*\n', '\n\n', optimized_code)
        
        return optimized_code
    except Exception as e:
        logger.error(f"Error optimizing {file_info['path']}: {str(e)}")
        return None

def get_language_specific_prompt(language):
    """Return language-specific additions to the main prompt."""
    prompts = {
        'Python': """
        For Python code, pay special attention to:
        - Use of eval(), exec() or other dynamic code execution
        - SQL injection vulnerabilities in database queries
        - Insecure use of pickle, yaml.load(), etc.
        - Unsafe file operations or path traversal issues
        """,
        'JavaScript': """
        For JavaScript code, pay special attention to:
        - XSS vulnerabilities (unsanitized inputs)
        - Prototype pollution
        - Insecure use of eval() or new Function()
        - Event handling security issues
        """,
        # More language-specific prompts would be included here
    }
    
    return prompts.get(language, "")

def analyze_with_llm(file_info, optimized_code, rate_limiter=None):
    """Send code to Ollama for analysis and get vulnerabilities."""
    # Apply rate limiting if provided
    if rate_limiter:
        rate_limiter.wait_if_needed()
    
    # Get language-specific prompt additions
    language_specific_prompt = get_language_specific_prompt(file_info['language'])
    
    prompt = f"""Analyze the following {file_info['language']} code for security vulnerabilities, code quality issues, and misconfigurations. 
Focus on:
1. Security vulnerabilities
2. Code quality issues that could lead to bugs
3. Misconfigurations or insecure defaults
4. Best practice violations

{language_specific_prompt}

Respond with a structured JSON with the following format:
{{
    "vulnerabilities": [
        {{
            "severity": "HIGH/MEDIUM/LOW",
            "type": "vulnerability type",
            "description": "detailed description",
            "line_number": "approximate line number if identifiable",
            "recommendation": "how to fix"
        }}
    ],
    "code_quality_issues": [
        {{
            "severity": "HIGH/MEDIUM/LOW",
            "description": "detailed description",
            "line_number": "approximate line number if identifiable",
            "recommendation": "how to fix"
        }}
    ],
    "misconfigurations": [
        {{
            "severity": "HIGH/MEDIUM/LOW",
            "description": "detailed description",
            "recommendation": "how to fix"
        }}
    ]
}}

If no issues are found in a category, return an empty array for that category.

Here's the code to analyze:

{optimized_code}

"""

    try:
        response = requests.post('http://localhost:11434/api/generate', 
                               json={
                                   "model": "gemma3:12b",
                                   "prompt": prompt,
                                   "stream": False,
                                   "format": "json"
                               },
                               timeout=300)  # 5-minute timeout
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', '{}')
        else:
            logger.error(f"Error calling Ollama API: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logger.error(f"Exception calling Ollama API: {str(e)}")
        return None

def format_results(file_info, analysis_result):
    """Format the analysis results into a markdown string."""
    try:
        # Try to parse as JSON for better formatting
        result_json = json.loads(analysis_result)
        formatted_result = f"## File: {file_info['path']}\n"
        formatted_result += f"Language: {file_info['language']}\n\n"
        
        # Add vulnerabilities
        if result_json.get('vulnerabilities'):
            formatted_result += "### Vulnerabilities\n"
            for vuln in result_json['vulnerabilities']:
                formatted_result += f"- **{vuln.get('severity', 'UNKNOWN')} - {vuln.get('type', 'Unknown')}**\n"
                formatted_result += f"  - Description: {vuln.get('description', 'No description')}\n"
                if vuln.get('line_number'):
                    formatted_result += f"  - Line: {vuln.get('line_number')}\n"
                formatted_result += f"  - Recommendation: {vuln.get('recommendation', 'No recommendation')}\n\n"
        
        # Add code quality issues
        if result_json.get('code_quality_issues'):
            formatted_result += "### Code Quality Issues\n"
            for issue in result_json['code_quality_issues']:
                formatted_result += f"- **{issue.get('severity', 'UNKNOWN')}**\n"
                formatted_result += f"  - Description: {issue.get('description', 'No description')}\n"
                if issue.get('line_number'):
                    formatted_result += f"  - Line: {issue.get('line_number')}\n"
                formatted_result += f"  - Recommendation: {issue.get('recommendation', 'No recommendation')}\n\n"
        
        # Add misconfigurations
        if result_json.get('misconfigurations'):
            formatted_result += "### Misconfigurations\n"
            for misconfig in result_json['misconfigurations']:
                formatted_result += f"- **{misconfig.get('severity', 'UNKNOWN')}**\n"
                formatted_result += f"  - Description: {misconfig.get('description', 'No description')}\n"
                formatted_result += f"  - Recommendation: {misconfig.get('recommendation', 'No recommendation')}\n\n"
        
        # If no issues were found
        if (not result_json.get('vulnerabilities') and 
            not result_json.get('code_quality_issues') and 
            not result_json.get('misconfigurations')):
            formatted_result += "No issues detected.\n\n"
        
        return formatted_result
        
    except json.JSONDecodeError:
        # If not valid JSON, create simpler format
        formatted_result = f"## File: {file_info['path']}\n"
        formatted_result += f"Language: {file_info['language']}\n\n"
        formatted_result += "### Analysis\n"
        formatted_result += analysis_result + "\n\n"
        return formatted_result

def write_results(results, output_file):
    """Append analysis results to the output file."""
    with open(output_file, 'a', encoding='utf-8') as f:
        f.write(results + "\n\n")

def process_file(file_info, output_file, rate_limiter=None):
    """Process a single file - optimize, analyze, and write results."""
    logger.info(f"Processing: {file_info['path']}")
    
    # Optimize code
    optimized_code = optimize_code(file_info)
    if not optimized_code:
        logger.warning(f"Skipping {file_info['path']} due to optimization error")
        return
    
    # Skip very large files to avoid context window issues
    if len(optimized_code) > 15000:
        logger.warning(f"Skipping {file_info['path']} - file too large ({len(optimized_code)} characters)")
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"## File: {file_info['path']}\n")
            f.write("Skipped - file too large for analysis\n\n")
        return
    
    # Analyze with LLM
    analysis_result = analyze_with_llm(file_info, optimized_code, rate_limiter)
    
    if not analysis_result:
        logger.warning(f"Skipping {file_info['path']} due to analysis error")
        return
    
    # Format results
    formatted_result = format_results(file_info, analysis_result)
    
    # Write to output file
    write_results(formatted_result, output_file)
    
    logger.info(f"Completed analysis of {file_info['path']}")
    return True

def process_files_parallel(files, output_file, max_workers=4, max_calls_per_minute=10):
    """Process files in parallel using a thread pool."""
    rate_limiter = RateLimiter(max_calls_per_minute)
    completed = 0
    total = len(files)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all files for processing
        future_to_file = {
            executor.submit(process_file, file_info, output_file, rate_limiter): file_info
            for file_info in files
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_file):
            file_info = future_to_file[future]
            try:
                result = future.result()
                completed += 1
                logger.info(f"Progress: {completed}/{total} files completed")
            except Exception as e:
                logger.error(f"Error processing {file_info['path']}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='SAST tool using Ollama and Gemma3 LLM')
    parser.add_argument('directory', help='Directory path to scan')
    parser.add_argument('--output', default='sast_results.md', help='Output file for results')
    parser.add_argument('--max-files', type=int, default=100, help='Maximum number of files to process')
    parser.add_argument('--exclude-dirs', nargs='+', help='Directories to exclude from analysis')
    parser.add_argument('--include-extensions', nargs='+', help='Only include specific file extensions (e.g., .py .js)')
    parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers')
    parser.add_argument('--rate-limit', type=int, default=10, help='Maximum LLM calls per minute')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Verify directory exists
    if not os.path.isdir(args.directory):
        logger.error(f"Error: Directory '{args.directory}' does not exist")
        sys.exit(1)
    
    # Process exclude_dirs
    exclude_dirs = DEFAULT_EXCLUDE_DIRS
    if args.exclude_dirs:
        exclude_dirs = args.exclude_dirs
    
    # Process include_extensions
    include_extensions = None
    if args.include_extensions:
        include_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in args.include_extensions]
    
    # Create output file with header
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f"# SAST Analysis Results\n\n")
        f.write(f"Directory: {os.path.abspath(args.directory)}\n")
        f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # Check if Ollama is running
    try:
        response = requests.get('http://localhost:11434/api/version', timeout=5)
        if response.status_code != 200:
            logger.error(f"Ollama server is not responding correctly: {response.status_code}")
            sys.exit(1)
    except requests.exceptions.RequestException:
        logger.error("Ollama server is not running. Please start Ollama before running this tool.")
        sys.exit(1)
    
    # Scan directory for files
    files = scan_directory(args.directory, exclude_dirs, include_extensions)
    logger.info(f"Found {len(files)} files to analyze")
    
    # Limit number of files to analyze
    if len(files) > args.max_files:
        logger.info(f"Limiting analysis to {args.max_files} files")
        files = files[:args.max_files]
    
    # Process files in parallel
    process_files_parallel(
        files, 
        args.output, 
        max_workers=args.workers,
        max_calls_per_minute=args.rate_limit
    )
    
    logger.info(f"Analysis complete. Results written to {args.output}")

if __name__ == "__main__":
    main()
