"""
Tests for the SecretPatterns class.
"""

from secret_guardian.patterns import SecretPatterns


class TestSecretPatterns:
    """Tests for the SecretPatterns class."""

    def test_patterns_initialization(self):
        """Test patterns initialization."""
        patterns = SecretPatterns()
        pattern_dict = patterns.get_patterns()

        assert len(pattern_dict) > 0
        assert "aws_access_key" in pattern_dict
        assert "github_token" in pattern_dict
        assert "google_api_key" in pattern_dict

    def test_aws_access_key_pattern(self):
        """Test AWS Access Key pattern."""
        patterns = SecretPatterns()
        aws_pattern = patterns.get_patterns()["aws_access_key"]

        # Positive cases
        assert aws_pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert aws_pattern.search("AKIA1234567890123456")

        # Negative cases
        assert not aws_pattern.search("BKIAIOSFODNN7EXAMPLE")  # No empieza con AKIA
        assert not aws_pattern.search("AKIA123")  # Muy corto

    def test_github_token_pattern(self):
        """Test del patrón de GitHub token."""
        patterns = SecretPatterns()
        github_pattern = patterns.get_patterns()["github_token"]

        # Positive cases
        assert github_pattern.search("ghp_1234567890123456789012345678901234567890")
        assert github_pattern.search("gho_1234567890123456789012345678901234567890")
        assert github_pattern.search("ghu_1234567890123456789012345678901234567890")

        # Negative cases
        assert not github_pattern.search("ghx_123")  # Incorrect prefix

    def test_google_api_key_pattern(self):
        """Test del patrón de Google API Key."""
        patterns = SecretPatterns()
        google_pattern = patterns.get_patterns()["google_api_key"]

        # Positive cases
        assert google_pattern.search("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI")
        assert google_pattern.search("AIzaAbCdEfGhIjKlMnOpQrStUvWxYz1234567890")

        # Negative cases
        assert not google_pattern.search(
            "BIzaSyDdI0hCZtE6vySjMm"
        )  # Doesn't start with AIza
        assert not google_pattern.search("AIza123")  # Too short

    def test_jwt_token_pattern(self):
        """Test del patrón de JWT token."""
        patterns = SecretPatterns()
        jwt_pattern = patterns.get_patterns()["jwt_token"]

        # Positive case
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert jwt_pattern.search(jwt_token)

        # Negative case
        assert not jwt_pattern.search("not.a.jwt.token")

    def test_private_key_pattern(self):
        """Test del patrón de clave privada."""
        patterns = SecretPatterns()
        private_key_pattern = patterns.get_patterns()["private_key"]

        # Positive case
        assert private_key_pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert private_key_pattern.search("-----BEGIN PRIVATE KEY-----")

        # Negative case
        assert not private_key_pattern.search("-----BEGIN PUBLIC KEY-----")

    def test_slack_token_pattern(self):
        """Test del patrón de Slack token."""
        patterns = SecretPatterns()
        slack_pattern = patterns.get_patterns()["slack_token"]

        # Positive cases
        assert slack_pattern.search("xoxb-123-456-789")
        assert slack_pattern.search("xoxa-1-2-3-abcdef")
        assert slack_pattern.search(
            "xoxp-123456789012-123456789012-123456789012-abcdef"
        )

        # Negative cases
        assert not slack_pattern.search("yoxb-123-456")  # Incorrect prefix

    def test_add_custom_pattern(self):
        """Test de agregar patrón personalizado."""
        patterns = SecretPatterns()

        # Add custom pattern
        patterns.add_custom_pattern("custom_test", r"CUSTOM_[A-Z0-9]{10}")

        custom_pattern = patterns.get_patterns()["custom_test"]
        assert custom_pattern.search("CUSTOM_ABCDEFGHIJ")
        assert not custom_pattern.search("CUSTOM_ABC")  # Too short

    def test_remove_pattern(self):
        """Test de remover patrón."""
        patterns = SecretPatterns()

        # Verify pattern exists
        assert "aws_access_key" in patterns.get_patterns()

        # Remove pattern
        result = patterns.remove_pattern("aws_access_key")
        assert result is True
        assert "aws_access_key" not in patterns.get_patterns()

        # Try to remove non-existent pattern
        result = patterns.remove_pattern("nonexistent_pattern")
        assert result is False

    def test_get_pattern_names(self):
        """Test de obtener nombres de patrones."""
        patterns = SecretPatterns()
        names = patterns.get_pattern_names()

        assert isinstance(names, list)
        assert len(names) > 0
        assert "aws_access_key" in names
        assert "github_token" in names

    def test_database_url_pattern(self):
        """Test del patrón de Database URL."""
        patterns = SecretPatterns()
        db_pattern = patterns.get_patterns()["database_url"]

        # Casos positivos
        test_cases = [
            'DATABASE_URL = "postgresql://user:pass@localhost:5432/db"',
            'DB_URL: "mysql://root:password@127.0.0.1:3306/mydb"',
            'database_url = "mongodb://user:pass@localhost:27017/db"',
            'db_url: "redis://localhost:6379"',
        ]

        for case in test_cases:
            assert db_pattern.search(case), f"Failed for: {case}"

        # Casos negativos
        assert not db_pattern.search('URL = "http://example.com"')
        assert not db_pattern.search('DATABASE = "mydb"')

    def test_generic_api_key_pattern(self):
        """Test del patrón de API key genérica."""
        patterns = SecretPatterns()
        api_pattern = patterns.get_patterns()["generic_api_key"]

        # Casos positivos
        test_cases = [
            'API_KEY = "abcdef1234567890abcdef123"',
            'api_secret: "super_secret_key_123456789"',
            'APIKEY = "my-api-key-with-dashes-123"',
        ]

        for case in test_cases:
            match = api_pattern.search(case)
            assert match, f"Failed for: {case}"

    def test_case_insensitive_patterns(self):
        """Test que los patrones son case-insensitive."""
        patterns = SecretPatterns()
        api_pattern = patterns.get_patterns()["generic_api_key"]

        # Diferentes casos - necesitan tener al menos 20 caracteres
        test_cases = [
            'API_KEY = "test123456789012345678"',
            'api_key = "test123456789012345678"',
            'Api_Key = "test123456789012345678"',
            'API-KEY = "test123456789012345678"',
        ]

        for case in test_cases:
            assert api_pattern.search(case), f"Case sensitivity failed for: {case}"
