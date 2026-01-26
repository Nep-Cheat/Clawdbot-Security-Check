---
name: clawdbot-security-check
description: Perform a read-only security analysis of Clawdbot's own configuration to identify hardening opportunities. Scans for the top 10 security vulnerabilities without modifying any settings. Use when user asks to "run security check", "audit clawdbot", "scan for vulnerabilities", or "check security hardening".
homepage: https://github.com/TheSethRose/Clawdbot-Security-Check
metadata: {"clawdbot":{"emoji":"🔒","os":["darwin","linux"],"requires":{"node":">=18.0.0"},"install":[{"id":"skill-install","kind":"clone","repo":"https://github.com/TheSethRose/Clawdbot-Security-Check.git","label":"Clone Clawdbot Security Check repository","bins":["security-check.js"]}]}}
---

# Clawdbot Security Check

Run a comprehensive read-only security audit of your Clawdbot installation.

## When to Use

- User says "run security check", "audit clawdbot", or "check security"
- User asks about vulnerabilities or hardening options
- Periodic security review requests
- After configuration changes

## How to Run

### Prerequisites

Ensure the skill is installed:
```bash
git clone https://github.com/TheSethRose/Clawdbot-Security-Check.git
```

### Execution

**Option 1: Direct Node.js execution**
```bash
cd Clawdbot-Security-Check
node security-check.js
```

**Option 2: JSON output for programmatic parsing**
```bash
node security-check.js --json
```

**Option 3: Via Clawdbot**
```
@clawdbot run security-check
```

## What Gets Checked

| # | Vulnerability | Severity | Check Method |
|---|---------------|----------|--------------|
| 1 | Gateway exposed on 0.0.0.0:18789 | 🔴 Critical | Inspect `gateway.bind_address` and `gateway.auth_token` |
| 2 | DM policy allows all users | 🟠 High | Verify `dm_policy` is `allowlist` with users defined |
| 3 | Sandbox disabled by default | 🟠 High | Confirm `sandbox=all` and `docker.network=none` |
| 4 | Credentials in plaintext oauth.json | 🔴 Critical | Check file existence + permissions |
| 5 | Prompt injection via web content | 🟡 Medium | Validate `wrap_untrusted_content` is enabled |
| 6 | Dangerous commands unblocked | 🟠 High | Review `blocked_commands` array for rm/curl/git force |
| 7 | No network isolation | 🟡 Medium | Check `docker.network` setting |
| 8 | Elevated tool access granted | 🟡 Medium | Verify `restrict_tools` is true |
| 9 | No audit logging enabled | 🟡 Medium | Confirm `audit_logging` is enabled |
| 10 | Weak/default pairing codes | 🟡 Medium | Validate `code_length` >= 8 + rate limiting |

## Config Locations Scanned

The skill checks these locations in order:
1. `~/.clawdbot/config.json`
2. `~/.clawdbot/config.yaml`
3. `~/.clawdbot/.clawdbotrc`
4. `.clawdbotrc` (current working directory)

## Interpreting Results

### Summary Line
- ✅ **Passed** - No issues found for this check
- ⚠️ **Warning** - Medium severity concern
- 🔴 **Critical** - Immediate action required

### Finding Format
Each finding includes:
- **Severity level** - Critical, High, Medium, or Info
- **Current state** - What's misconfigured
- **Recommendation** - Specific fix to apply

## Example Output

```
═══════════════════════════════════════════════════════════════
🔒 CLAWDBOT SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════════════════
Generated: 2026-01-26T15:30:00.000Z

┌─ SUMMARY ───────────────────────────────────────────────
│ ✅ Passed:     7
│ ⚠️  Warnings:   2
│ 🔴 Critical:   1
└────────────────────────────────────────────────────────

┌─ FINDINGS ──────────────────────────────────────────────
│ 🔴 [CRITICAL] Gateway Exposure
│    Finding: Gateway exposed on 0.0.0.0:18789 without authentication
│    → Set gateway.auth_token in environment variables
│
│ 🟠 [HIGH] DM Policy
│    Finding: DM policy is "allow" - allows all users
│    → Set dm_policy to allowlist with explicit users
└────────────────────────────────────────────────────────

This is a READ-ONLY analysis. No changes were made.
```

## Important Notes

- **100% Read-Only** - This skill never modifies your configuration
- **Zero Dependencies** - Uses only Node.js built-in modules
- **No Network Calls** - All analysis is local
- **JSON Output** - Use `--json` flag for programmatic integration

## Security Philosophy

> "Security through transparency." — ᴅᴀɴɪᴇʟ ᴍɪᴇssʟᴇʀ

This skill is inspired by the Clawdbot hardening framework shared by [Daniel Miessler](https://x.com/DanielMiessler/status/2015865548714975475). The goal is visibility into configuration risks without making changes—you remain in full control.

## Troubleshooting

- **"No config found"** - Ensure Clawdbot is installed and config exists
- **Permission errors** - Check file permissions on config files
- **Node version error** - Requires Node.js 18+

## Limitations

- Does not check remote/remote Clawdbot instances
- Cannot scan containerized deployments remotely
- Does not validate actual network exposure (run `netstat` separately)
