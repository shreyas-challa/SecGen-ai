"""
main.py — CLI entry point for the AI Security Research Agent.

Usage:
    python main.py <target> [options]

Examples:
    python main.py 192.168.1.10 --dry-run --scope 192.168.1.0/24
    python main.py example.com --scope example.com --max-iter 20
    python main.py 10.10.10.5 --scope 10.10.10.0/24 --output-dir ./reports
"""
from __future__ import annotations

import argparse
import sys

from config import load_config, Config
from scope import ScopeEnforcer
from session_log import SessionLogger
from agent import SecurityAgent


AUTHORIZATION_PHRASE = "YES I HAVE AUTHORIZATION"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Security Research Agent — Claude-powered autonomous penetration tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        help="Target IP address, hostname, or domain to test.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=None,
        help="Simulate all tool calls without executing them (overrides .env DRY_RUN).",
    )
    parser.add_argument(
        "--scope",
        metavar="SCOPE",
        help=(
            "Comma-separated allowed scope (IPs, CIDRs, or domains). "
            "Overrides ALLOWED_SCOPE from .env."
        ),
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=None,
        metavar="N",
        help="Maximum agent iterations (overrides MAX_ITERATIONS from .env).",
    )
    parser.add_argument(
        "--output-dir",
        metavar="PATH",
        default=None,
        help="Directory for reports and session logs (overrides OUTPUT_DIR from .env).",
    )
    return parser.parse_args()


def confirm_target(target: str, scope_list: list, dry_run: bool) -> None:
    """
    Display the target/scope and require the operator to type an explicit
    authorization phrase before continuing.
    """
    mode = "DRY RUN (no real network activity)" if dry_run else "LIVE (real network scanning)"
    scope_str = ", ".join(scope_list) if scope_list else "(auto: " + target + ")"

    print()
    print("=" * 60)
    print("  AI SECURITY RESEARCH AGENT")
    print("=" * 60)
    print(f"  Target  : {target}")
    print(f"  Scope   : {scope_str}")
    print(f"  Mode    : {mode}")
    print("=" * 60)
    print()
    print("WARNING: This tool performs active security testing.")
    print("You must have explicit written authorization to test this target.")
    print()
    print(f'Type exactly: {AUTHORIZATION_PHRASE}')
    print()

    try:
        user_input = input("> ").strip()
    except EOFError:
        user_input = ""

    if user_input != AUTHORIZATION_PHRASE:
        print("\n[!] Authorization not confirmed. Aborting.")
        sys.exit(1)

    print("\n[+] Authorization confirmed. Starting agent...\n")


def apply_cli_overrides(config: Config, args: argparse.Namespace) -> Config:
    """
    Return a new Config with CLI flags applied on top of .env values.
    Uses object.__setattr__ since Config is a frozen dataclass.
    """
    import copy

    # Build a mutable dict from the frozen dataclass
    fields = {k: getattr(config, k) for k in config.__dataclass_fields__}

    if args.dry_run is not None:
        fields["dry_run"] = args.dry_run

    if args.scope is not None:
        fields["allowed_scope"] = [s.strip() for s in args.scope.split(",") if s.strip()]

    if args.max_iter is not None:
        fields["max_iterations"] = args.max_iter

    if args.output_dir is not None:
        fields["output_dir"] = args.output_dir

    return Config(**fields)


def main() -> None:
    args = parse_args()

    # Load base config from .env
    try:
        config = load_config()
    except EnvironmentError as exc:
        print(f"[!] Configuration error: {exc}")
        sys.exit(1)

    # Apply CLI overrides
    config = apply_cli_overrides(config, args)

    target = args.target.strip()

    # Ensure the target is always in scope (auto-add if scope is empty)
    scope_list = list(config.allowed_scope)
    if not scope_list:
        scope_list = [target]
        # Rebuild config with auto-scope
        fields = {k: getattr(config, k) for k in config.__dataclass_fields__}
        fields["allowed_scope"] = scope_list
        config = Config(**fields)

    # Authorization gate
    confirm_target(target, scope_list, config.dry_run)

    # Wire components
    scope_enforcer = ScopeEnforcer(config.allowed_scope)

    import os
    os.makedirs(config.output_dir, exist_ok=True)
    session_logger = SessionLogger(config.output_dir, target)

    print(f"[*] Session log: {session_logger.log_path}")
    print(f"[*] Model: {config.claude_model}")
    print(f"[*] Max iterations: {config.max_iterations}")
    print()

    agent = SecurityAgent(
        config=config,
        scope=scope_enforcer,
        target=target,
        session_logger=session_logger,
    )

    try:
        report_path = agent.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Session log preserved.", flush=True)
        session_logger.log_session_end(
            reason="keyboard_interrupt",
            iterations_used=0,
            report_path=None,
        )
        sys.exit(130)

    if report_path:
        print(f"\n[+] Report: {report_path}")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
