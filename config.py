"""
config.py — Configuration dataclass loaded from .env
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    # Anthropic
    anthropic_api_key: str
    claude_model: str

    # Metasploit RPC
    msf_host: str
    msf_port: int
    msf_user: str
    msf_password: str
    msf_ssl: bool

    # Tool binary paths
    nmap_path: str
    nuclei_path: str
    ffuf_path: str
    sqlmap_path: str

    # Wordlists
    default_wordlist: str
    subdomains_wordlist: str

    # Nuclei templates directory
    nuclei_templates_path: str

    # Agent behaviour
    agent_mode: str          # "htb" (aggressive) or "pentest" (conservative)
    lhost: str               # Attacker IP for reverse shells (e.g. tun0 on HTB VPN)
    lport: int               # Default listener port
    shell_timeout: int       # Default shell command timeout in seconds
    max_iterations: int
    dry_run: bool

    # Scope (comma-separated list of IPs, CIDR ranges, or domain strings)
    allowed_scope: List[str]

    # Output directory for reports and session logs
    output_dir: str


def load_config() -> Config:
    """Load configuration from .env file (if present) and environment variables."""
    load_dotenv()

    def _bool(key: str, default: bool = False) -> bool:
        return os.getenv(key, str(default)).lower() in ("1", "true", "yes")

    def _int(key: str, default: int = 0) -> int:
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            return default

    def _list(key: str, default: str = "") -> List[str]:
        raw = os.getenv(key, default).strip()
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY is not set. "
            "Copy .env.example to .env and fill in your API key."
        )

    return Config(
        anthropic_api_key=api_key,
        claude_model=os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"),

        msf_host=os.getenv("MSF_HOST", "127.0.0.1"),
        msf_port=_int("MSF_PORT", 55553),
        msf_user=os.getenv("MSF_USER", "msf"),
        msf_password=os.getenv("MSF_PASSWORD", ""),
        msf_ssl=_bool("MSF_SSL", False),

        nmap_path=os.getenv("NMAP_PATH", "nmap"),
        nuclei_path=os.getenv("NUCLEI_PATH", "nuclei"),
        ffuf_path=os.getenv("FFUF_PATH", "ffuf"),
        sqlmap_path=os.getenv("SQLMAP_PATH", "sqlmap"),

        default_wordlist=os.getenv(
            "DEFAULT_WORDLIST",
            "/usr/share/wordlists/dirb/common.txt",
        ),
        subdomains_wordlist=os.getenv(
            "SUBDOMAINS_WORDLIST",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ),
        nuclei_templates_path=os.getenv("NUCLEI_TEMPLATES", ""),

        agent_mode=os.getenv("AGENT_MODE", "htb"),
        lhost=os.getenv("LHOST", ""),
        lport=_int("LPORT", 4444),
        shell_timeout=_int("SHELL_TIMEOUT", 120),
        max_iterations=_int("MAX_ITERATIONS", 30),
        dry_run=_bool("DRY_RUN", False),

        allowed_scope=_list("ALLOWED_SCOPE"),
        output_dir=os.getenv("OUTPUT_DIR", "./output"),
    )
