"""
main.py — CLI entry point for the AI Security Research Agent.

Usage:
    python main.py <target> [options]

Examples:
    python main.py 192.168.1.10 --dry-run --scope 192.168.1.0/24
    python main.py example.com --scope example.com --max-iter 20
    python main.py 10.10.10.5 --mode htb --lhost 10.10.14.5 --scope 10.10.10.0/24
"""
from __future__ import annotations

import argparse
import sys

from config import load_config, Config
from scope import ScopeEnforcer
from session_log import SessionLogger
from agent import SecurityAgent


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
    parser.add_argument(
        "--mode",
        choices=["htb", "pentest"],
        default=None,
        help="Agent mode: 'htb' (aggressive, full exploitation) or 'pentest' (conservative). Overrides AGENT_MODE from .env.",
    )
    parser.add_argument(
        "--lhost",
        metavar="IP",
        default=None,
        help="Attacker IP for reverse shells (e.g. your tun0 IP on HTB VPN). Overrides LHOST from .env.",
    )
    parser.add_argument(
        "--lport",
        type=int,
        metavar="PORT",
        default=None,
        help="Default listener port for reverse shells (default 4444). Overrides LPORT from .env.",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Disable the real-time browser-based attack graph UI.",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=5000,
        metavar="PORT",
        help="Port for the attack graph UI server (default 5000).",
    )
    return parser.parse_args()


def show_banner(target: str, scope_list: list, dry_run: bool, mode: str, lhost: str, lport: int, provider: str = "anthropic", model: str = "") -> None:
    mode_display = {
        "htb": "HTB (aggressive — full exploitation)",
        "pentest": "PENTEST (conservative — PoC only)",
    }.get(mode, mode)

    if dry_run:
        mode_display += " [DRY RUN]"

    scope_str = ", ".join(scope_list) if scope_list else "(auto: " + target + ")"

    print()
    print("=" * 60)
    print("  AI SECURITY RESEARCH AGENT")
    print("=" * 60)
    print(f"  Target  : {target}")
    print(f"  Scope   : {scope_str}")
    print(f"  Mode    : {mode_display}")
    print(f"  Provider: {provider} ({model})")
    if lhost:
        print(f"  LHOST   : {lhost}:{lport}")
    print("=" * 60)
    print()


def apply_cli_overrides(config: Config, args: argparse.Namespace) -> Config:
    """
    Return a new Config with CLI flags applied on top of .env values.
    """
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

    if args.mode is not None:
        fields["agent_mode"] = args.mode

    if args.lhost is not None:
        fields["lhost"] = args.lhost

    if args.lport is not None:
        fields["lport"] = args.lport

    return Config(**fields)


def _print_shell_handoff(agent: SecurityAgent) -> None:
    """Print active shell info and connection instructions after the agent finishes."""
    active_pids = agent.get_active_shells()
    if not active_pids:
        return

    print()
    print("=" * 60)
    print("  ACTIVE SHELL SESSIONS")
    print("=" * 60)
    print(f"  Background processes still running: {len(active_pids)}")
    for pid in active_pids:
        print(f"    PID: {pid}")
    print()
    print("  These may include reverse shell listeners or SSH sessions.")
    print("  Check the report for connection details.")
    print("  To clean up, terminate the PIDs above or press Ctrl+C.")
    print("=" * 60)
    print()


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

    # Ensure the target is always in scope
    scope_list = list(config.allowed_scope)
    if target not in scope_list:
        scope_list.append(target)
    # Rebuild config with updated scope
    fields = {k: getattr(config, k) for k in config.__dataclass_fields__}
    fields["allowed_scope"] = scope_list
    config = Config(**fields)

    show_banner(target, scope_list, config.dry_run, config.agent_mode, config.lhost, config.lport, config.provider, config.claude_model)

    # Warn if HTB mode without LHOST
    if config.agent_mode == "htb" and not config.lhost:
        print("[!] WARNING: HTB mode without --lhost. Reverse shells will not work.")
        print("[!] Set LHOST in .env or pass --lhost <your-tun0-ip>")
        print()

    # Wire components
    scope_enforcer = ScopeEnforcer(config.allowed_scope)

    import os
    os.makedirs(config.output_dir, exist_ok=True)
    session_logger = SessionLogger(config.output_dir, target)

    print(f"[*] Session log: {session_logger.log_path}")
    cache_note = " + prompt caching" if config.provider == "openrouter" else " (prompt caching)"
    print(f"[*] Provider: {config.provider}{cache_note} | Model: {config.claude_model}")
    print(f"[*] Max iterations: {config.max_iterations} (HTB mode may auto-increase to 50)")
    print(f"[*] Agent mode: {config.agent_mode}")
    print(f"[*] Context: max_result={config.max_tool_result_chars}c  history={config.max_history_turns} turns  delay={config.min_iter_delay}s")
    print()

    # Start attack graph UI (unless --no-ui)
    graph_updater = None
    if not getattr(args, 'no_ui', False):
        try:
            from graph_state import GraphState
            from graph_updater import GraphUpdater
            import ui_server
            gs = GraphState()
            gs._status_target = target
            graph_updater = GraphUpdater(gs)
            ui_server.start_server(gs, port=args.ui_port)
            ui_server._status["target"] = target
            print(f"[UI] Attack graph live at http://localhost:{args.ui_port}")
            print()
        except ImportError as e:
            print(f"[UI] Skipping graph UI (missing dependency: {e})")
            print()

    agent = SecurityAgent(
        config=config,
        scope=scope_enforcer,
        target=target,
        session_logger=session_logger,
        graph_updater=graph_updater,
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

    # Shell handoff — show active sessions
    _print_shell_handoff(agent)

    if report_path:
        print(f"\n[+] Report: {report_path}")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
