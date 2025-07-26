# Secret Guardian

A Python library for detecting secrets and API keys 

## Development

This project uses [Poetry](https://python-poetry.org/) for dependency management and [Ruff](https://docs.astral.sh/ruff/) as linter and formatter.

## Features

- **Automatic detection** of multiple types of secrets and API keys
- **Built-in patterns** for AWS, GitHub, Google, Slack, JWT and more
- **Protection verification** with `.env` and `.gitignore` files
- **Customizable patterns** for specific use cases
- **CLI interface** for CI/CD integration
- **Detailed reports** in text or JSON format
- **Smart filtering** of false positives
- **Hardcoded secret detection** anywhere in source code

## Installation

```bash
pip install secret-guardian
```

## Usage

### As a Python library

```python
from secret_guardian import SecretScanner, SecretFoundError

# Scan a repository
scanner = SecretScanner("./my-project")

try:
    # Scan and raise exception if secrets are found
    matches = scanner.scan(raise_on_secrets=True)
    print("No secrets found")
except SecretFoundError as e:
    print(f"Found {len(e.secrets_found)} secrets")
    
    # Generate report
    report = scanner.generate_report(e.secrets_found)
    print(report)
```

### Command line interface

```bash
# Scan current repository
secret-guardian scan .

# Scan with custom options
secret-guardian scan ./my-project --no-env-check --output json

# View statistics
secret-guardian stats .

# List available patterns
secret-guardian patterns
```

## Detected Patterns

- **AWS**: Access Keys, Secret Keys
- **GitHub**: Personal Access Tokens, Classic Tokens
- **Google**: API Keys
- **Slack**: Bot Tokens, User Tokens
- **JWT**: JSON Web Tokens
- **Database**: Connection URLs
- **Private keys**: RSA, SSH
- **Generic API Keys**
- **Passwords**

## License

MIT License. See `LICENSE` for more details..