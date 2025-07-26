"""
Patterns for detecting different types of secrets and API keys.
"""

import re
from typing import Dict, List, Pattern


class SecretPatterns:
    """Class containing patterns for detecting secrets and API keys."""

    def __init__(self) -> None:
        """Initialize detection patterns."""
        self._patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, Pattern[str]]:
        """Load all secret detection patterns."""
        patterns = {
            # Generic API Keys
            "generic_api_key": re.compile(
                r"(?i)(api[_-]?key|apikey|api[_-]?secret)"
                r'["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{20,})',
                re.IGNORECASE,
            ),
            # AWS
            "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
            "aws_secret_key": re.compile(
                r"(?i)(aws[_-]?secret[_-]?access[_-]?key|"
                r'aws[_-]?secret)["\s]*[:=]["\s]*([a-zA-Z0-9/+=]{40})',
                re.IGNORECASE,
            ),
            # GitHub
            "github_token": re.compile(
                r"gh[pousr]_[A-Za-z0-9_]{36,255}", re.IGNORECASE
            ),
            "github_classic_token": re.compile(
                r'github[_-]?token["\s]*[:=]["\s]*([a-zA-Z0-9_]{40})', re.IGNORECASE
            ),
            # Google API
            "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}", re.IGNORECASE),
            # Slack
            "slack_token": re.compile(
                r"xox[baprs]-[0-9a-zA-Z\-]{10,72}", re.IGNORECASE
            ),
            # JWT Tokens
            "jwt_token": re.compile(
                r"eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*",
                re.IGNORECASE,
            ),
            # Database URLs
            "database_url": re.compile(
                r'(?i)(database[_-]?url|db[_-]?url)["\s]*[:=]["\s]*'
                r'(postgresql|mysql|mongodb|redis)://[^\s"\']+',
                re.IGNORECASE,
            ),
            # Generic passwords
            "generic_password": re.compile(
                r'(?i)(password|passwd|pwd)["\s]*[:=]["\s]*' r'([^"\s]{8,})',
                re.IGNORECASE,
            ),
            # Private keys
            "private_key": re.compile(
                r"-----BEGIN[A-Z\s]+PRIVATE KEY-----", re.IGNORECASE
            ),
            # Authentication tokens
            "auth_token": re.compile(
                r"(?i)(auth[_-]?token|access[_-]?token|bearer[_-]?token)"
                r'["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{20,})',
                re.IGNORECASE,
            ),
        }
        return patterns

    def get_patterns(self) -> Dict[str, Pattern[str]]:
        """Return all loaded patterns."""
        return dict(self._patterns)

    def get_pattern_names(self) -> List[str]:
        """Return names of all available patterns."""
        return list(self._patterns.keys())

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """Add a custom pattern."""
        self._patterns[name] = re.compile(pattern, re.IGNORECASE)

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name."""
        if name in self._patterns:
            del self._patterns[name]
            return True
        return False
