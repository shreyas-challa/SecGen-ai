# SecGen-AI

An autonomous penetration testing agent powered by Claude. Point it at a target, and it drives through the entire pentest lifecycle — from reconnaissance to exploitation to privilege escalation to report — by itself using Claude's tool-use capability.

The agent automates work that normally takes security researchers hours of manual effort.

Claude acts as the brain — it decides what to scan, interprets results, chains actions, exploits vulnerabilities, escalates privileges, and produces a detailed report. External tools (nmap, nuclei, ffuf, sqlmap, metasploit) plus arbitrary shell commands are wrapped as Claude tools.

---

## Features

- **Two modes**: HTB (aggressive, full root) and Pentest (conservative, PoC-only)
- **Two LLM providers**: Anthropic (direct, with prompt caching) or OpenRouter (higher rate limits, OpenAI-compatible)
- **8 tool integrations**: nmap, nuclei, ffuf, sqlmap, metasploit, HTTP requests, shell commands, report generation
- **SSH credential store**: Discovered SSH credentials are stored and auto-applied via sshpass on subsequent commands — no manual credential plumbing needed
- **Prompt caching**: Anthropic provider caches the system prompt and tool definitions across iterations, significantly reducing token costs
- **Rate limit retry**: Exponential backoff on API rate limit errors for both providers
- **Full attack chain**: Recon → vuln analysis → exploitation → privesc → flag capture → report
- **Scope enforcement**: Every tool call is validated against the declared scope
- **Structured reports**: Markdown reports with attack chain, flags, shell proof, privesc details, and connection info
- **Session logging**: Every tool call and Claude reasoning step logged to JSONL
- **Dry-run mode**: Test the full agent loop without touching the network

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env — set your API key for whichever provider you want to use

# 3. Make sure tools are in PATH (or set paths in .env)
nmap --version
nuclei --version
ffuf --version
sqlmap --version
```

### Choosing a Provider

Set `PROVIDER` in `.env` to `anthropic` or `openrouter`.

- **`anthropic`** — Direct Anthropic API. Enables prompt caching (reduces costs on long runs). Can hit rate limits on free/low tier.
- **`openrouter`** — Routes through OpenRouter. Higher rate limits, same Claude models. No prompt caching.

```bash
# Anthropic (default)
PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxxxx

# OpenRouter
PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-xxxxx
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROVIDER` | `anthropic` | LLM provider: `anthropic` or `openrouter` |
| `ANTHROPIC_API_KEY` | — | Required when `PROVIDER=anthropic` |
| `OPENROUTER_API_KEY` | — | Required when `PROVIDER=openrouter` |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model to use |
| `AGENT_MODE` | `htb` | `htb` (aggressive) or `pentest` (conservative) |
| `LHOST` | — | Your attacker IP (tun0 on HTB VPN) for reverse shells |
| `LPORT` | `4444` | Default listener port for reverse shells |
| `SHELL_TIMEOUT` | `120` | Default timeout (seconds) for shell commands |
| `MAX_ITERATIONS` | `30` | Max agent loop iterations (HTB mode auto-bumps to 50) |
| `DRY_RUN` | `false` | Simulate all tool calls without real execution |
| `ALLOWED_SCOPE` | — | Comma-separated IPs, CIDRs, or domains |
| `OUTPUT_DIR` | `./output` | Directory for reports and session logs |

See `.env.example` for the full list including Metasploit RPC, tool paths, and wordlist settings.

---

## Usage

### HTB Mode (default) — Full Exploitation

```bash
# Target an HTB box with your VPN IP for reverse shells
python main.py 10.10.10.5 --lhost 10.10.14.5

# Explicit scope and custom listener port
python main.py 10.10.10.5 --lhost 10.10.14.5 --lport 9001 --scope 10.10.10.0/24

# Override mode from CLI
python main.py 10.10.10.5 --mode htb --lhost 10.10.14.5
```

**HTB mode runs 6 phases:**
1. **Enumeration** — Full port scan, directory brute-force, service fingerprinting, SMB/FTP/DNS enumeration
2. **Vulnerability Analysis** — Nuclei scan, nmap vuln scripts, searchsploit, CVE correlation
3. **Exploitation** — Download/compile exploits, set up listeners, deploy shells, get initial access
4. **Privilege Escalation** — sudo -l, SUID binaries, cron jobs, LinPEAS, exploit privesc vector
5. **Flag Capture** — Read user.txt and root.txt, capture proof (whoami, id)
6. **Reporting** — Full report with attack chain, flags, shell proof, and connection info

### Pentest Mode — Conservative PoC

```bash
# Conservative mode — no active exploitation
python main.py 192.168.1.10 --mode pentest --scope 192.168.1.0/24
```

**Pentest mode runs 4 phases:**
1. Reconnaissance
2. Vulnerability Assessment
3. Exploitation (PoC only, non-destructive)
4. Reporting

### Common Options

```bash
# Dry run — test the full loop without network activity
python main.py 127.0.0.1 --dry-run --scope 127.0.0.1

# Custom iteration limit
python main.py 10.10.10.5 --max-iter 20 --lhost 10.10.14.5

# Custom output directory
python main.py 10.10.10.5 --output-dir ./reports --lhost 10.10.14.5
```

### CLI Reference

```
positional arguments:
  target                Target IP address, hostname, or domain to test

options:
  --dry-run             Simulate all tool calls without executing them
  --scope SCOPE         Comma-separated allowed scope (IPs, CIDRs, or domains)
  --max-iter N          Maximum agent iterations
  --output-dir PATH     Directory for reports and session logs
  --mode {htb,pentest}  Agent mode: htb (aggressive) or pentest (conservative)
  --lhost IP            Attacker IP for reverse shells (your tun0 IP)
  --lport PORT          Default listener port (default 4444)
```

---

## Tools

The agent has 8 tools available:

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port/service enumeration, version detection, NSE vuln scripts |
| `nuclei_scan` | Template-based vulnerability scanning |
| `ffuf_scan` | Directory/file brute-force and subdomain enumeration |
| `sqlmap_scan` | SQL injection detection and exploitation |
| `metasploit_run` | Metasploit module execution via msfrpc |
| `http_request` | Raw HTTP requests for fingerprinting and custom payloads |
| `shell_command` | Arbitrary shell execution, background process management, SSH credential storage |
| `generate_report` | Final markdown report generation |

### Shell Command Tool

The `shell_command` tool supports five actions:

- **`run`** — Execute a command and wait for output (with configurable timeout)
- **`run_background`** — Start a process in the background (e.g. `nc -lvnp 4444`), returns PID
- **`check_background`** — Read current stdout/stderr from a background process
- **`stop_background`** — Terminate a background process
- **`store_credentials`** — Store SSH credentials for a host (`host`, `username`, `password`). All subsequent `ssh user@host` commands targeting that host are automatically wrapped with `sshpass` — no manual credential plumbing needed.

Output is capped at 10KB per command to avoid context window overflow. Background processes are automatically cleaned up on exit.

---

## Test Commands

```bash
# 1. Dry run — verifies the full loop works without network activity
python main.py 127.0.0.1 --dry-run --scope 127.0.0.1

# 2. Scope violation test — agent should log SCOPE_VIOLATION and continue
python main.py 8.8.8.8 --dry-run --scope 10.0.0.0/24

# 3. HTB dry run with LHOST
python main.py 10.10.10.5 --dry-run --mode htb --lhost 10.10.14.5 --scope 10.10.10.0/24

# 4. Pentest mode dry run
python main.py 192.168.1.10 --dry-run --mode pentest --scope 192.168.1.0/24

# 5. Cap iterations to see early-stop behaviour
python main.py 127.0.0.1 --dry-run --max-iter 5

# 6. Real scan against a local lab VM
python main.py 192.168.56.101 --scope 192.168.56.0/24 --max-iter 15

# 7. Real HTB box (replace with your target and VPN IP)
python main.py 10.10.10.5 --lhost 10.10.14.5
```

Reports: `./output/report_<target>_<timestamp>.md`
Session logs: `./output/session_<target>_<timestamp>.jsonl`

---

## Metasploit (optional)

```bash
# Start the RPC daemon before running the agent
msfrpcd -P yourpassword -S -a 127.0.0.1

# Set in .env
MSF_PASSWORD=yourpassword
```

Metasploit defaults to `check_only=true` in pentest mode. In HTB mode, the agent may fire exploits after confirming vulnerability.

---

## Project Structure

```
main.py              CLI entry point + shell handoff
agent.py             Claude tool-use loop + token/cache metrics
config.py            Config dataclass (.env loader)
llm_client.py        Anthropic and OpenRouter provider clients
scope.py             Scope enforcement (ScopeViolation)
session_log.py       JSONL audit logger
system_prompt.py     Dual-mode methodology prompt (HTB / pentest)
tools/
  definitions.py     8 Claude tool schemas
  dispatcher.py      Routes calls + error boundary
  shell_tool.py      Shell execution, background process mgmt, SSH credential store
  nmap_tool.py       Nmap scanner
  nuclei_tool.py     Nuclei scanner
  ffuf_tool.py       Ffuf web fuzzer
  sqlmap_tool.py     SQLMap injection tester
  metasploit_tool.py Metasploit RPC client
  http_tool.py       HTTP request handler
  report_tool.py     Markdown report generator
```

---

## How It Works

1. **User provides a target** via CLI with optional mode, scope, and attacker IP
2. **Agent loop starts** — Claude receives the system prompt with the methodology and available tools
3. **Claude reasons and calls tools** — each tool call is scope-checked, executed (or simulated in dry-run), and the result is fed back
4. **Agent iterates** through phases — enumeration, vulnerability analysis, exploitation, privesc
5. **SSH credentials are auto-managed** — when credentials are found, the agent stores them; all subsequent SSH commands are auto-wrapped with sshpass
6. **Report is generated** — structured markdown with all findings, attack chain, and proof
7. **Shell handoff** — if background processes (listeners, shells) are still active, connection info is printed

The entire conversation (Claude's reasoning + tool calls + results) is logged to a JSONL session file for audit and replay.

### Token & Cache Metrics

When using the Anthropic provider, the agent prints token usage and prompt cache metrics after each iteration:

```
stop_reason=tool_use  in=4821 out=312 cache_read=4590 cache_create=231
```

The system prompt and tool definitions (~5K tokens) are cached after the first iteration, so subsequent calls only pay for new message tokens.
