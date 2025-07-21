"""
Secret Guardian - Detects secrets and API keys in repositories.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .exceptions import RepositoryError, SecretFoundError, SecretGuardianError
from .patterns import SecretPatterns
from .scanner import SecretScanner

__all__ = [
    "SecretScanner",
    "SecretPatterns",
    "SecretGuardianError",
    "SecretFoundError",
    "RepositoryError",
]
