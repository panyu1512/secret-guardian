from typing import TYPE_CHECKING, Optional, Sequence

if TYPE_CHECKING:
    from .scanner import SecretMatch


class SecretGuardianError(Exception):
    """Base exception for Secret Guardian."""

    pass


class SecretFoundError(SecretGuardianError):
    """Exception raised when secrets are found in the code."""

    def __init__(
        self,
        secrets_found: Sequence["SecretMatch"],
        message: Optional[str] = None,
    ):
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
