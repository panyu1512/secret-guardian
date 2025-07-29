"""
Secret Guardian - Detects secrets and API keys in repositories.
"""

__version__ = "0.1.0"
__author__ = "panyu1512"
__email__ = "kikeferreragius@gmail.com"

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
