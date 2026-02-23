# SecGen-AI

An autonomous penetration testing agent powered by Claude. Point it at a target, it drives through recon → vuln assessment → exploitation PoC → report by itself using tool use.

Claude acts as the brain — it decides what to scan, interprets results, and chains the next action. External tools (nmap, nuclei, ffuf, sqlmap, metasploit) are wrapped as Claude tools.

---

## What it does

1. **Recon** — nmap port/service scan, ffuf directory/subdomain brute-force, HTTP fingerprinting
2. **Vuln Assessment** — nuclei template scan, nmap vuln scripts, manual HTTP probing
3. **Exploitation PoC** — sqlmap for SQLi, Metasploit `check` (safe by default), custom HTTP payloads
4. **Report** — structured markdown report with severity-sorted findings, evidence, PoC steps, remediation

Every tool call and Claude reasoning step is logged to a JSONL session file.

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY

# 3. Make sure tools are in PATH (or set paths in .env)
nmap --version
nuclei --version
ffuf --version
sqlmap --version
```

---

## Running

```bash
# Basic — auto-adds target to scope
python main.py <target>

# Dry run (no real network calls, safe to test logic)
python main.py 127.0.0.1 --dry-run

# With explicit scope
python main.py 192.168.1.10 --scope 192.168.1.0/24

# Full options
python main.py 10.10.10.5 --scope 10.10.10.0/24 --max-iter 20 --output-dir ./reports
```

You must type `YES I HAVE AUTHORIZATION` at the prompt before the agent starts.

---

## Test Commands

```bash
# 1. Dry run — verifies the full loop works without touching the network
python main.py 127.0.0.1 --dry-run --scope 127.0.0.1

# 2. Scope violation test — agent should log SCOPE_VIOLATION and continue
#    Set scope to 10.0.0.0/24 and target something outside it
python main.py 8.8.8.8 --dry-run --scope 10.0.0.0/24

# 3. Real scan against localhost (nmap/ffuf must be installed)
python main.py 127.0.0.1 --scope 127.0.0.1

# 4. Real scan against a local lab VM
python main.py 192.168.56.101 --scope 192.168.56.0/24 --max-iter 15

# 5. Cap iterations to see early-stop behaviour
python main.py 127.0.0.1 --dry-run --max-iter 5
```

Reports land in `./output/report_<target>_<timestamp>.md`.
Session logs land in `./output/session_<target>_<timestamp>.jsonl`.

---

## Metasploit (optional)

```bash
# Start the RPC daemon before running the agent
msfrpcd -P yourpassword -S -a 127.0.0.1

# Set in .env
MSF_PASSWORD=yourpassword
```

Metasploit defaults to `check_only=true` — it verifies exploitability without firing a payload.

---

## Project Structure

```
main.py              CLI + authorization gate
agent.py             Claude tool-use loop
config.py            Config dataclass (.env loader)
scope.py             Scope enforcement (ScopeViolation)
session_log.py       JSONL audit logger
system_prompt.py     Pentest methodology prompt
tools/
  definitions.py     7 Claude tool schemas
  dispatcher.py      Routes calls + error boundary
  nmap_tool.py
  nuclei_tool.py
  ffuf_tool.py
  sqlmap_tool.py
  metasploit_tool.py
  http_tool.py
  report_tool.py
```
