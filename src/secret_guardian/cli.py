"""
Command line interface for Secret Guardian.
"""

import sys
from pathlib import Path

import click

from . import __version__
from .exceptions import SecretGuardianError
from .scanner import SecretScanner


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Secret Guardian - Detect secrets and API keys in repositories."""
    pass


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option(
    "--no-env-check", is_flag=True, help="Disable .env protection verification"
)
@click.option("--exclude", multiple=True, help="Additional file patterns to exclude")
@click.option(
    "--output",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option(
    "--fail-on-secrets/--no-fail-on-secrets",
    default=True,
    help="Fail if secrets are found (useful for CI/CD)",
)
def scan(
    repo_path: str,
    no_env_check: bool,
    exclude: tuple,
    output: str,
    fail_on_secrets: bool,
) -> None:
    """Scan a repository for secrets."""
    try:
        scanner = SecretScanner(
            repo_path=repo_path,
            exclude_patterns=list(exclude) if exclude else None,
            check_env_protection=not no_env_check,
        )

        matches = scanner.scan(raise_on_secrets=False)

        if output == "json":
            import json

            result = {
                "secrets_found": len(matches),
                "files_scanned": len(list(Path(repo_path).rglob("*"))),
                "matches": [
                    {
                        "file": match.file_path,
                        "line": match.line_number,
                        "pattern": match.pattern_name,
                        "text": match.matched_text,
                    }
                    for match in matches
                ],
            }
            click.echo(json.dumps(result, indent=2))
        else:
            report = scanner.generate_report(matches)
            click.echo(report)

        if matches and fail_on_secrets:
            sys.exit(1)

    except SecretGuardianError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
def stats(repo_path: str) -> None:
    """Show repository statistics."""
    try:
        scanner = SecretScanner(repo_path=repo_path)
        stats_data = scanner.get_stats()

        click.echo("📊 REPOSITORY STATISTICS")
        click.echo("=" * 30)
        total_secrets = stats_data.get("total_secrets", 0)
        click.echo(f"Secrets found: {total_secrets}")
        files_with_secrets = stats_data.get("files_with_secrets", 0)
        click.echo(f"Files with secrets: {files_with_secrets}")
        env_vars = stats_data.get("env_vars_found", 0)
        click.echo(f".env variables found: {env_vars}")

        env_protected = stats_data.get("env_protection", 0)
        status = "✅ Protected" if env_protected else "❌ Not protected"
        click.echo(f".env protection: {status}")

    except SecretGuardianError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def patterns() -> None:
    """List all available detection patterns."""
    from .patterns import SecretPatterns

    patterns_obj = SecretPatterns()
    pattern_names = patterns_obj.get_pattern_names()

    click.echo("🔍 AVAILABLE DETECTION PATTERNS")
    click.echo("=" * 35)

    for i, name in enumerate(sorted(pattern_names), 1):
        click.echo(f"{i:2d}. {name}")


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
