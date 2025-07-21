"""
Custom exceptions for Secret Guardian.
"""


class SecretGuardianError(Exception):
    """Base exception for Secret Guardian."""

    pass


class SecretFoundError(SecretGuardianError):
    """Exception raised when secrets are found in the code."""

    def __init__(self, secrets_found: list, message: str = None):
        self.secrets_found = secrets_found
        if message is None:
            count = len(secrets_found)
            message = f"Found {count} secrets in the code"
        super().__init__(message)


class RepositoryError(SecretGuardianError):
    """Exception for repository-related errors."""

    pass


class ConfigurationError(SecretGuardianError):
    """Exception for configuration errors."""

    pass
