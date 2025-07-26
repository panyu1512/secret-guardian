"""
Main scanner for detecting secrets in repositories.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from .exceptions import RepositoryError, SecretFoundError
from .patterns import SecretPatterns


@dataclass
class SecretMatch:
    """Represents a secret found in the code."""

    file_path: str
    line_number: int
    pattern_name: str
    matched_text: str
    line_content: str
    confidence: float = 1.0


class SecretScanner:
    """
    Main scanner for detecting secrets and API keys in repositories.
    """

    def __init__(
        self,
        repo_path: str,
        custom_patterns: Optional[Dict[str, str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        check_env_protection: bool = True,
    ):
        """
        Initialize the secret scanner.

        Args:
            repo_path: Path to the repository to scan
            custom_patterns: Additional custom patterns
            exclude_patterns: File patterns to exclude
            check_env_protection: Check if secrets are in .env files
        """
        self.repo_path = Path(repo_path)
        self.check_env_protection = check_env_protection

        # Validate directory exists
        if not self.repo_path.exists():
            raise RepositoryError(f"Directory does not exist: {repo_path}")

        # Initialize patterns
        self.patterns = SecretPatterns()
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                self.patterns.add_custom_pattern(name, pattern)

        # Default file patterns to exclude
        self.exclude_patterns = exclude_patterns or [
            r"\.git/",
            r"\.venv/",
            r"__pycache__/",
            r"node_modules/",
            r"\.env$",
            r"\.env\.",
            r"\.log$",
            r"\.pyc$",
            r"\.pyo$",
            r"\.jpg$",
            r"\.png$",
            r"\.gif$",
            r"\.pdf$",
            r"\.zip$",
            r"\.tar\.gz$",
        ]

        # Protected environment variables
        self.env_vars: Set[str] = set()
        self._load_env_vars()

        # Check .gitignore protection
        self.gitignore_protects_env = self._check_gitignore_protection()

    def _load_env_vars(self) -> None:
        """Load environment variables from .env files."""
        env_files = [
            self.repo_path / ".env",
            self.repo_path / ".env.local",
            self.repo_path / ".env.development",
            self.repo_path / ".env.production",
        ]

        for env_file in env_files:
            if env_file.exists():
                # Load variables without applying them to environment
                with open(env_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line and not line.startswith("#"):
                            var_name = line.split("=")[0].strip()
                            self.env_vars.add(var_name)

    def _check_gitignore_protection(self) -> bool:
        """Check if .env files are protected in .gitignore."""
        gitignore_path = self.repo_path / ".gitignore"
        if not gitignore_path.exists():
            return False

        try:
            with open(gitignore_path, encoding="utf-8") as f:
                content = f.read()
                # Look for common .env patterns
                env_patterns = [".env", "*.env", ".env*"]
                return any(pattern in content for pattern in env_patterns)
        except Exception:
            return False

    def _should_exclude_file(self, file_path: Path) -> bool:
        """Determine if a file should be excluded from scanning."""
        relative_path = str(file_path.relative_to(self.repo_path))

        for pattern in self.exclude_patterns:
            if re.search(pattern, relative_path):
                return True

        return False

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is binary."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                return b"\0" in chunk
        except Exception:
            return True

    def _scan_file(self, file_path: Path) -> List[SecretMatch]:
        """Scan an individual file for secrets."""
        matches: List[SecretMatch] = []

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return matches

        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern in self.patterns.get_patterns().items():
                for match in pattern.finditer(line):
                    secret_match = SecretMatch(
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num,
                        pattern_name=pattern_name,
                        matched_text=match.group(),
                        line_content=line.strip(),
                    )
                    matches.append(secret_match)

        return matches

    def _filter_false_positives(self, matches: List[SecretMatch]) -> List[SecretMatch]:
        """Filter common false positives."""
        filtered_matches = []

        for match in matches:
            # Filter example variables or placeholders
            if any(
                placeholder in match.matched_text.lower()
                for placeholder in [
                    "placeholder",
                    "your_key",
                    "your_secret",
                    "insert_key",
                    "replace_with",
                    "todo",
                    "xxx",
                    "yyy",
                    "dummy",
                    "fake",
                    "sample",
                    "demo",
                    "example_key",
                    "test_key",
                ]
            ):
                continue

            # Filter commented lines
            stripped_line = match.line_content.strip()
            if (
                stripped_line.startswith("#")
                or stripped_line.startswith("//")
                or stripped_line.startswith("/*")
            ):
                continue

            # Filter regex pattern definitions (like in patterns.py)
            if any(
                code_pattern in match.line_content
                for code_pattern in [
                    "re.compile(",
                    "regex.compile(",
                    "Pattern(",
                    "pattern =",
                    "PATTERN =",
                    '"[A-Z_][A-Z0-9_]*":',
                    'r"',
                    "r'",
                ]
            ):
                continue

            # Check if this is a hardcoded secret (not using env variables)
            is_hardcoded = self._is_hardcoded_secret(match)

            # If it's hardcoded, it's definitely a security issue
            if is_hardcoded:
                match.confidence = 0.9  # High confidence for hardcoded secrets
                filtered_matches.append(match)
            else:
                # If using env vars properly and .env is protected
                if self.check_env_protection:
                    var_match = re.search(
                        r"([A-Z_][A-Z0-9_]*)\s*[:=]", match.line_content
                    )
                    if var_match:
                        var_name = var_match.group(1)
                        if var_name in self.env_vars and self.gitignore_protects_env:
                            # This variable is properly managed in .env
                            continue

                # Otherwise include with lower confidence
                match.confidence = 0.6
                filtered_matches.append(match)

        return filtered_matches

    def _is_hardcoded_secret(self, match: SecretMatch) -> bool:
        """Check if a secret appears to be hardcoded in the source code."""
        line = match.line_content.lower()

        # Look for patterns that indicate hardcoded values
        hardcoded_indicators = [
            # Direct assignment with quotes
            r'["\']([a-zA-Z0-9_\-+/=]{16,})["\']',
            # Assignment operators
            r'[:=]\s*["\']',
            # Common hardcoded patterns
            r'token\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'key\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'secret\s*[:=]\s*["\'][^"\']{10,}["\']',
            r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
        ]

        # Check if line contains hardcoded patterns
        for pattern in hardcoded_indicators:
            if re.search(pattern, line):
                # Additional check: make sure it's not using os.getenv()
                if not any(
                    env_func in line
                    for env_func in [
                        "os.getenv",
                        "os.environ",
                        "getenv",
                        "env.get",
                        "process.env",
                        "$env:",
                        "${",
                        "config.get",
                    ]
                ):
                    return True

        return False

    def scan(
        self,
        raise_on_secrets: bool = False,
        include_env_check: Optional[bool] = None,
    ) -> List[SecretMatch]:
        """
        Scan the repository for secrets and API keys.

        Args:
            raise_on_secrets: Whether to raise exception when secrets are found
            include_env_check: Include .env protection verification

        Returns:
            List of secrets found

        Raises:
            SecretFoundError: If secrets are found and raise_on_secrets=True
        """
        if include_env_check is not None:
            self.check_env_protection = include_env_check

        all_matches = []

        # Iterate over all files in the repository
        for file_path in self.repo_path.rglob("*"):
            if not file_path.is_file():
                continue

            if self._should_exclude_file(file_path):
                continue

            if self._is_binary_file(file_path):
                continue

            matches = self._scan_file(file_path)
            all_matches.extend(matches)

        # Filter false positives
        filtered_matches = self._filter_false_positives(all_matches)

        # Always report if secrets are found
        if filtered_matches:
            count = len(filtered_matches)
            high_conf = [m for m in filtered_matches if m.confidence > 0.8]
            hardcoded_count = len(high_conf)

            if hardcoded_count > 0:
                msg = f"🚨 CRITICAL: {hardcoded_count} hardcoded secrets " f"detected!"
                print(msg)
                print("   These secrets are directly embedded in your code!")

            if count > hardcoded_count:
                other_count = count - hardcoded_count
                msg = f"⚠️  WARNING: {other_count} other potential secrets found"
                print(msg)

            print(f"\n📋 Details of all {count} findings:")
            for match in filtered_matches:
                file_info = f"{match.file_path}:{match.line_number}"
                icon = "🔥" if match.confidence > 0.8 else "⚠️"
                pattern = match.pattern_name
                print(f"   {icon} {file_info} - {pattern}")
                if match.confidence > 0.8:
                    secret_preview = match.matched_text[:30]
                    print(f"      HARDCODED: {secret_preview}...")

            if not self.gitignore_protects_env and self.env_vars:
                msg = "📝 NOTE: .env files are not properly protected!"
                print(f"\n{msg}")
                print("   Add .env* to your .gitignore file")

        if filtered_matches and raise_on_secrets:
            raise SecretFoundError(
                filtered_matches, f"Found {len(filtered_matches)} secrets in the code"
            )

        return filtered_matches

    def generate_report(self, matches: List[SecretMatch]) -> str:
        """Generate a detailed report of found secrets."""
        if not matches:
            return "✅ No secrets found in the repository."

        count = len(matches)
        hardcoded = [m for m in matches if m.confidence > 0.8]
        hardcoded_count = len(hardcoded)

        report = f"🚨 SECURITY REPORT - {count} secrets found\n"
        if hardcoded_count > 0:
            report += f"   🔥 {hardcoded_count} are HARDCODED in source code!\n"
        report += "=" * 60 + "\n\n"

        # Group by file
        files_with_secrets: Dict[str, List[SecretMatch]] = {}
        for match in matches:
            if match.file_path not in files_with_secrets:
                files_with_secrets[match.file_path] = []
            files_with_secrets[match.file_path].append(match)

        for file_path, file_matches in files_with_secrets.items():
            report += f"📄 File: {file_path}\n"
            report += "-" * 40 + "\n"

            for match in file_matches:
                line_info = f"Line {match.line_number}: {match.pattern_name}"
                if match.confidence > 0.8:
                    severity = "🔥 HARDCODED"
                else:
                    severity = "⚠️  Potential"
                report += f"  {severity} - {line_info}\n"
                report += f"     Found: {match.matched_text}\n"
                report += f"     Context: {match.line_content}\n"
                if match.confidence > 0.8:
                    msg = "     ❗ This secret is embedded directly in code!\n"
                    report += msg
                report += "\n"

        # Recommendations
        report += "💡 RECOMMENDATIONS:\n"
        report += "-" * 20 + "\n"
        if hardcoded_count > 0:
            msg = "1. 🚨 URGENT: Remove hardcoded secrets from source code\n"
            report += msg
            report += "2. Move ALL secrets to .env files\n"
            msg = "3. Use environment variables: os.getenv('SECRET_NAME')\n"
            report += msg
            report += "4. Add .env* to .gitignore\n"
            report += "5. Regenerate any exposed secrets/keys\n"
        else:
            report += "1. Move secrets to .env files\n"
            report += "2. Add .env* to .gitignore\n"
            report += "3. Use environment variables in production\n"

        if not self.gitignore_protects_env:
            report += "⚠️  Your .gitignore doesn't protect .env files\n"

        return report

    def get_stats(self) -> Dict[str, int]:
        """Get statistics from the last scan."""
        try:
            matches = self.scan(raise_on_secrets=False)

            stats = {
                "total_secrets": len(matches),
                "files_with_secrets": len({m.file_path for m in matches}),
                "env_protection": 1 if self.gitignore_protects_env else 0,
                "env_vars_found": len(self.env_vars),
            }

            # Count by pattern type
            for match in matches:
                pattern_key = f"pattern_{match.pattern_name}"
                stats[pattern_key] = stats.get(pattern_key, 0) + 1

            return stats
        except Exception:
            return {"error": 1}
