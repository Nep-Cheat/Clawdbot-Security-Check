# Clawdbot Security Check

🔒 **Read-only security analysis tool for Clawdbot configurations**

A read-only security scanner that analyzes Clawdbot installations for the top 10 security vulnerabilities without making any changes to your configuration.

## Features

- ✅ **100% Read-Only** - Never modifies settings or files
- 🔍 **10 Security Checks** - Covers all major Clawdbot hardening areas
- 📊 **Detailed Reports** - Human-readable and JSON output formats
- 🚀 **Zero Dependencies** - Uses only Node.js built-ins
- 🔧 **Multiple Config Locations** - Auto-detects common config paths

## Security Checks

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 1 | Gateway Exposure | 🔴 Critical | Detects unbound gateway with no auth token |
| 2 | DM Policy | 🟠 High | Verifies allowlist-based DM restrictions |
| 3 | Sandbox | 🟠 High | Confirms Docker sandbox isolation is enabled |
| 4 | Credentials | 🔴 Critical | Finds plaintext credential files |
| 5 | Prompt Injection | 🟡 Medium | Checks for untrusted content wrapping |
| 6 | Dangerous Commands | 🟠 High | Validates command blocking configuration |
| 7 | Network Isolation | 🟡 Medium | Verifies Docker network restrictions |
| 8 | Elevated Access | 🟡 Medium | Checks MCP tool restrictions |
| 9 | Audit Logging | 🟡 Medium | Confirms session logging is enabled |
| 10| Pairing Codes | 🟡 Medium | Validates cryptographic randomness |

## Installation

```bash
# Clone or download
git clone https://github.com/TheSethRose/Clawdbot-Security-Check.git
cd Clawdbot-Security-Check

# Make executable
chmod +x security-check.js
```

## Usage

### Quick Scan
```bash
node security-check.js
```

### JSON Output (for automation)
```bash
node security-check.js --json
```

### As a Clawdbot Skill
Copy the skill to your Clawdbot skills directory:
```bash
cp -r Clawdbot-Security-Check ~/.clawdbot/skills/
```

Then use via Clawdbot:
```
@clawdbot run security-check
```

## Output Example

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
│    Check if gateway is exposed on 0.0.0.0 without auth token
│    Finding: Gateway exposed on 0.0.0.0:18789 without authentication
│    → Set gateway.auth_token in environment variables
│
│ 🟠 [HIGH] DM Policy
│    Check if DM policy is set to allowlist
│    Finding: DM policy is "allow" - allows all users
│    → Set dm_policy to allowlist with explicit users
│
└────────────────────────────────────────────────────────

This is a READ-ONLY analysis. No changes were made.
```

## Config Locations Checked

The tool checks these locations for Clawdbot configuration:
- `~/.clawdbot/config.json`
- `~/.clawdbot/config.yaml`
- `~/.clawdbot/.clawdbotrc`
- `.clawdbotrc` (current directory)

## Remediations

Each finding includes a specific recommendation. Common fixes:

### 1. Gateway Authentication
```bash
export CLAWDBOT_AUTH_TOKEN="your-secure-random-token"
```

### 2. DM Allowlist
```json
{
  "dm_policy": "allowlist",
  "dm_policy_allowlist": ["@trusteduser1", "@trusteduser2"]
}
```

### 3. Sandbox Isolation
```json
{
  "sandbox": "all",
  "docker": {
    "network": "none"
  }
}
```

### 4. Credential Security
```bash
chmod 600 ~/.clawdbot/oauth.json
```

## Contributing

1. Fork the repository
2. Add new security checks to `CHECKS` array
3. Update `skill.json` with new check IDs
4. Submit a PR

## License

MIT - Security-first, open source forever.

---

**Remember**: This tool is read-only. It identifies issues but never modifies your configuration. You remain in full control of all security decisions.
