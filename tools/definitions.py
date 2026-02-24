"""
tools/definitions.py — Claude tool JSON schemas for the security agent.

These 8 definitions are passed in the ``tools`` parameter of every
``client.messages.create()`` call so Claude knows what tools are available
and what parameters each accepts.
"""
from __future__ import annotations

from typing import List

TOOL_DEFINITIONS: List[dict] = [
    # ------------------------------------------------------------------ #
    # 1. nmap_scan                                                         #
    # ------------------------------------------------------------------ #
    {
        "name": "nmap_scan",
        "description": (
            "Run an nmap scan against a target to enumerate open ports, services, "
            "versions, and optionally run NSE vulnerability scripts. "
            "Returns structured JSON with host/port/service information."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, or CIDR range to scan (must be in scope).",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["stealth", "connect", "udp", "vuln", "version"],
                    "description": (
                        "Scan technique: "
                        "'stealth' = SYN scan (-sS), "
                        "'connect' = TCP connect (-sT), "
                        "'udp' = UDP scan (-sU), "
                        "'vuln' = NSE vuln scripts (--script=vuln), "
                        "'version' = service/version detection (-sV -sC)."
                    ),
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification, e.g. '80,443', '1-1024', 'top1000'. Defaults to top 1000 ports.",
                },
                "extra_flags": {
                    "type": "string",
                    "description": "Additional raw nmap flags, e.g. '--script=http-title --open'.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait for the scan to complete (default 300).",
                    "default": 300,
                },
            },
            "required": ["target", "scan_type"],
        },
    },

    # ------------------------------------------------------------------ #
    # 2. nuclei_scan                                                       #
    # ------------------------------------------------------------------ #
    {
        "name": "nuclei_scan",
        "description": (
            "Run Nuclei template-based vulnerability scanning against a target URL. "
            "Returns a list of findings with template ID, severity, matcher, and evidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or host (e.g. 'http://192.168.1.10' or 'example.com').",
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of template IDs or directories to use "
                        "(e.g. ['cves', 'exposures/configs', 'default-logins']). "
                        "Leave empty to use all templates."
                    ),
                },
                "severity": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info", "unknown"],
                    },
                    "description": "Filter results to these severity levels.",
                },
                "extra_flags": {
                    "type": "string",
                    "description": "Additional raw nuclei flags.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait (default 300).",
                    "default": 300,
                },
            },
            "required": ["target"],
        },
    },

    # ------------------------------------------------------------------ #
    # 3. ffuf_scan                                                         #
    # ------------------------------------------------------------------ #
    {
        "name": "ffuf_scan",
        "description": (
            "Run ffuf (Fuzz Faster U Fool) for web content discovery. "
            "Supports directory/file bruteforcing and virtual-host/subdomain enumeration."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": (
                        "Base URL for directory mode (e.g. 'http://192.168.1.10') "
                        "or domain for subdomain mode (e.g. 'example.com')."
                    ),
                },
                "scan_mode": {
                    "type": "string",
                    "enum": ["directory", "subdomain"],
                    "description": "'directory' bruteforces paths; 'subdomain' fuzzes the Host header.",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Absolute path to wordlist file. Uses config default if omitted.",
                },
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated extensions to append (e.g. 'php,html,txt'). Directory mode only.",
                },
                "filter_status": {
                    "type": "string",
                    "description": "HTTP status codes to filter OUT (e.g. '404,400'). Defaults to '404'.",
                    "default": "404",
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of concurrent threads (default 40).",
                    "default": 40,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait (default 120).",
                    "default": 120,
                },
            },
            "required": ["target", "scan_mode"],
        },
    },

    # ------------------------------------------------------------------ #
    # 4. sqlmap_scan                                                       #
    # ------------------------------------------------------------------ #
    {
        "name": "sqlmap_scan",
        "description": (
            "Run sqlmap to test a URL parameter for SQL injection vulnerabilities. "
            "Runs non-interactively (--batch). Returns whether the target is vulnerable "
            "and details of any injection points found."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL to test, e.g. 'http://target.com/page.php?id=1'.",
                },
                "parameter": {
                    "type": "string",
                    "description": "Specific parameter to test (e.g. 'id'). Tests all if omitted.",
                },
                "level": {
                    "type": "integer",
                    "description": "Test level 1-5 (default 1). Higher = more tests, more noise.",
                    "default": 1,
                },
                "risk": {
                    "type": "integer",
                    "description": "Risk level 1-3 (default 1). Higher = more dangerous payloads.",
                    "default": 1,
                },
                "dump_tables": {
                    "type": "boolean",
                    "description": "If true, attempt to enumerate and dump database tables (default false).",
                    "default": False,
                },
                "extra_flags": {
                    "type": "string",
                    "description": "Additional raw sqlmap flags.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait (default 180).",
                    "default": 180,
                },
            },
            "required": ["url"],
        },
    },

    # ------------------------------------------------------------------ #
    # 5. metasploit_run                                                    #
    # ------------------------------------------------------------------ #
    {
        "name": "metasploit_run",
        "description": (
            "Execute a Metasploit Framework module via the msfrpc daemon. "
            "ALWAYS use check_only=true first to verify exploitability without firing the payload. "
            "Requires msfrpcd to be running (see README)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "module_path": {
                    "type": "string",
                    "description": "Full module path, e.g. 'exploit/unix/ftp/vsftpd_234_backdoor'.",
                },
                "options": {
                    "type": "object",
                    "description": "Key/value pairs for module options, e.g. {'RHOSTS': '192.168.1.5', 'RPORT': '21'}.",
                    "additionalProperties": {"type": "string"},
                },
                "check_only": {
                    "type": "boolean",
                    "description": "If true, run 'check' instead of 'run' (safe verification). Default true.",
                    "default": True,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait for module to complete (default 120).",
                    "default": 120,
                },
            },
            "required": ["module_path"],
        },
    },

    # ------------------------------------------------------------------ #
    # 6. http_request                                                      #
    # ------------------------------------------------------------------ #
    {
        "name": "http_request",
        "description": (
            "Send a raw HTTP request to a URL and return the response. "
            "Useful for manual fingerprinting, confirming vulnerabilities, and crafting custom PoCs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL, e.g. 'http://192.168.1.10/admin'.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "description": "HTTP method (default GET).",
                    "default": "GET",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom request headers as key/value pairs.",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT requests).",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Whether to follow HTTP redirects (default true).",
                    "default": True,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default 30).",
                    "default": 30,
                },
            },
            "required": ["url"],
        },
    },

    # ------------------------------------------------------------------ #
    # 7. shell_command                                                     #
    # ------------------------------------------------------------------ #
    {
        "name": "shell_command",
        "description": (
            "Execute an arbitrary shell command on the local machine. "
            "Use this for anything not covered by specialized tools: SSH into targets, "
            "set up reverse shell listeners, compile exploits, run linpeas, "
            "enumerate services (smbclient, ftp, etc.), upload/download files, "
            "and perform privilege escalation. "
            "Supports foreground execution and background process management."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["run", "run_background", "check_background", "stop_background"],
                    "description": (
                        "'run' — execute and wait for completion; "
                        "'run_background' — start in background, return PID; "
                        "'check_background' — read output from background PID; "
                        "'stop_background' — terminate background PID."
                    ),
                },
                "command": {
                    "type": "string",
                    "description": (
                        "Shell command to execute (required for run/run_background). "
                        "Pipe through '| head -50' or '| grep -i keyword' to limit large outputs."
                    ),
                },
                "pid": {
                    "type": "integer",
                    "description": "PID of the background process (required for check_background/stop_background).",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Max seconds to wait for foreground commands (default 120).",
                    "default": 120,
                },
                "working_dir": {
                    "type": "string",
                    "description": "Working directory for the command. Defaults to output/workdir/.",
                },
                "input_data": {
                    "type": "string",
                    "description": "Data to pipe to the command's stdin. Use for commands that read from stdin (e.g. piping a password or script content).",
                },
            },
            "required": ["action"],
        },
    },

    # ------------------------------------------------------------------ #
    # 8. generate_report                                                   #
    # ------------------------------------------------------------------ #
    {
        "name": "generate_report",
        "description": (
            "Generate the final penetration test report in Markdown format. "
            "Call this ONCE when testing is complete. "
            "Findings are automatically sorted by severity."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The primary target that was tested.",
                },
                "executive_summary": {
                    "type": "string",
                    "description": "High-level summary for non-technical stakeholders (2-5 sentences).",
                },
                "findings": {
                    "type": "array",
                    "description": "List of individual security findings.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string", "description": "Short finding title."},
                            "severity": {
                                "type": "string",
                                "enum": ["Critical", "High", "Medium", "Low", "Info"],
                                "description": "Finding severity.",
                            },
                            "description": {
                                "type": "string",
                                "description": "Detailed technical description of the vulnerability.",
                            },
                            "evidence": {
                                "type": "string",
                                "description": "Raw output, request/response, or screenshot reference.",
                            },
                            "poc": {
                                "type": "string",
                                "description": "Step-by-step proof-of-concept reproduction steps.",
                            },
                            "remediation": {
                                "type": "string",
                                "description": "Concrete remediation advice.",
                            },
                        },
                        "required": ["title", "severity", "description"],
                    },
                },
                "methodology_notes": {
                    "type": "string",
                    "description": "Notes on testing methodology, tools used, and any limitations.",
                },
                "flags_captured": {
                    "type": "object",
                    "description": "Captured CTF flags (HTB mode).",
                    "properties": {
                        "user_flag": {
                            "type": "string",
                            "description": "Contents of user.txt",
                        },
                        "root_flag": {
                            "type": "string",
                            "description": "Contents of root.txt",
                        },
                    },
                },
                "attack_chain": {
                    "type": "array",
                    "description": "Ordered steps showing the path from recon to root.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "step": {
                                "type": "integer",
                                "description": "Step number in the chain.",
                            },
                            "phase": {
                                "type": "string",
                                "description": "Phase name (e.g. 'Enumeration', 'Exploitation', 'Privilege Escalation').",
                            },
                            "action": {
                                "type": "string",
                                "description": "What was done in this step.",
                            },
                            "result": {
                                "type": "string",
                                "description": "What the step achieved or revealed.",
                            },
                        },
                        "required": ["step", "phase", "action", "result"],
                    },
                },
                "shell_proof": {
                    "type": "string",
                    "description": "Command output proving shell access (e.g. output of 'whoami', 'id', 'hostname').",
                },
                "privilege_escalation": {
                    "type": "object",
                    "description": "Details of the privilege escalation vector used.",
                    "properties": {
                        "vector": {
                            "type": "string",
                            "description": "Name of the privesc vector (e.g. 'sudo misconfiguration', 'SUID binary').",
                        },
                        "description": {
                            "type": "string",
                            "description": "How the vector was exploited.",
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Command output or proof of escalation.",
                        },
                    },
                },
                "shell_access": {
                    "type": "object",
                    "description": "Connection info for the user to access the live shell.",
                    "properties": {
                        "method": {
                            "type": "string",
                            "description": "Connection method (e.g. 'SSH', 'reverse_shell', 'bind_shell', 'web_shell').",
                        },
                        "connection_info": {
                            "type": "string",
                            "description": "How to connect (e.g. 'ssh user@10.10.10.5 -p 22' or 'nc -nv 10.10.14.5 4444').",
                        },
                    },
                },
            },
            "required": ["target", "executive_summary", "findings"],
        },
    },
]
