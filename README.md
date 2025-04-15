
# Guide: Setting Up and Running a SAST Tool with Ollama and Gemma3:12b

This guide will walk you through the process of setting up and running a Static Application Security Testing (SAST) tool that leverages Gemma3:12b via Ollama to scan your codebase for vulnerabilities and misconfigurations.

## Prerequisites

- Python 3.8 or higher
- Git
- 16GB RAM minimum (24GB+ recommended)
- GPU with at least 12GB VRAM (16GB+ recommended for optimal performance)
- Linux, macOS, or Windows with WSL2


## Step 1: Install Ollama

Ollama is a lightweight local LLM server that allows you to run models like Gemma3:12b on your own hardware.

### For Linux and macOS:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```


### For Windows:

1. Install WSL2 if you haven't already
2. Download and install Ollama from the [official website](https://ollama.com/download)

Verify the installation by running:

```bash
ollama --version
```


## Step 2: Install Gemma3:12b Model

Pull the Gemma3:12b model from Ollama's model library:

```bash
ollama pull gemma3:12b
```

This will download and set up the model, which may take some time depending on your internet connection. The model is approximately 7-8GB in size after quantization.

If you have limited VRAM, you may want to use a more optimized quantization:

```bash
# For systems with less VRAM, use q4 quantization
ollama pull gemma3:12b-q4
```

Q4 quantization offers a good balance between performance and VRAM usage, allowing 12B models to run well even on GPUs with 16GB of VRAM.

## Step 3: Clone the SAST Tool Repository

```bash
git clone https://github.com/your-username/sast-tool.git
cd sast-tool
```


## Step 4: Install Dependencies

Create a virtual environment and install the required dependencies:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

The main dependencies include:

- requests (for API communication with Ollama)
- concurrent.futures (for parallel processing)
- logging (for detailed logging)


## Step 5: Configure the Tool

The SAST tool can be configured to scan specific file types and exclude certain directories. By default, it will scan common code and configuration files while excluding directories like `node_modules`, `venv`, and `.git`.

You can create a custom configuration file or use the default settings:

```bash
# Optional: Create a custom configuration file
cp config.example.json config.json

# Edit the configuration file if needed
nano config.json
```


## Step 6: Run the SAST Tool

Now you're ready to run the SAST tool on your codebase:

```bash
python sast_tool.py /path/to/your/project
```

Additional command line options:

```bash
# Specify a custom output file
python sast_tool.py /path/to/your/project --output results.md

# Limit the number of files to analyze
python sast_tool.py /path/to/your/project --max-files 50

# Exclude specific directories
python sast_tool.py /path/to/your/project --exclude-dirs node_modules dist .vscode

# Include only specific file extensions
python sast_tool.py /path/to/your/project --include-extensions .py .js .ts

# Set number of parallel workers
python sast_tool.py /path/to/your/project --workers 8

# Set maximum LLM calls per minute (rate limit)
python sast_tool.py /path/to/your/project --rate-limit 15

# Enable debug logging
python sast_tool.py /path/to/your/project --debug
```


## Step 7: Understanding the Results

The tool generates a markdown file with structured security findings for each analyzed file. The results include:

- **Vulnerabilities**: Security issues found in the code
- **Code Quality Issues**: Potential bugs or maintainability problems
- **Misconfigurations**: Configuration issues that could lead to security problems

Each finding includes:

- Severity level (HIGH, MEDIUM, LOW)
- Description of the issue
- Line number (when available)
- Recommendation for fixing the issue

Example output:

```markdown
# SAST Analysis Results

Directory: /path/to/your/project
Date: 2025-04-15 22:19:00

## File: /path/to/your/project/app.py
Language: Python

### Vulnerabilities
- **HIGH - SQL Injection**
  - Description: Unsanitized user input used in SQL query
  - Line: 42
  - Recommendation: Use parameterized queries instead of string concatenation

### Code Quality Issues
- **MEDIUM**
  - Description: Unused import statement
  - Line: 5
  - Recommendation: Remove unnecessary imports

## File: /path/to/your/project/config.json
Language: JSON

No issues detected.
```


## Step 8: Troubleshooting

### Common Issues

#### Ollama Connection Errors

If you encounter errors connecting to Ollama:

```
Error calling Ollama API: Connection refused
```

Make sure Ollama is running:

```bash
# Check if Ollama is running
ps aux | grep ollama

# Start Ollama if it's not running
ollama serve
```


#### Out of Memory Errors

If you encounter out of memory errors:

```
CUDA out of memory
```

Try the following solutions:

1. Use a more aggressive quantization for the model:

```bash
ollama pull gemma3:12b-q3
```

2. Reduce the number of parallel workers:

```bash
python sast_tool.py /path/to/your/project --workers 2
```

3. Limit the maximum file size:

```bash
python sast_tool.py /path/to/your/project --max-file-size 10000
```


#### Rate Limiting

If the tool seems to be too slow due to rate limiting, you can adjust the rate limit parameter:

```bash
python sast_tool.py /path/to/your/project --rate-limit 20
```

This allows more LLM calls per minute but may increase memory usage.

## Advanced Configuration

### Using SAST Results with VEX Documents

For a more comprehensive security approach, you can integrate the SAST tool with Vulnerability Exploitability eXchange (VEX) documents:

1. Generate VEX documents from the SAST results:

```bash
python sast_to_vex.py sast_results.md --output vex_docs/
```

2. Store the VEX documents in a `.vex/` directory in your repository:

```bash
mkdir -p .vex/
cp vex_docs/* .vex/
```


This helps prevent false positives in vulnerability scanning tools by documenting non-exploitable vulnerabilities.

### Custom Prompt Engineering

You can customize the prompts sent to the LLM for specific programming languages or security concerns:

1. Create a custom prompts file:

```bash
cp prompts.example.json prompts.json
```

2. Edit the file to add language-specific prompts or security focus areas
3. Use the custom prompts file:

```bash
python sast_tool.py /path/to/your/project --prompts-file prompts.json
```


This allows you to tailor the analysis to your specific needs and improve the quality of the results.
