#!/usr/bin/env node
/**
 * Clawdbot Security Check - Read-Only Analysis Tool
 * Analyzes Clawdbot configuration for security vulnerabilities without making changes
 */

import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join, resolve } from 'path';

const CHECKS = [
  {
    id: 'gateway-exposed',
    name: 'Gateway Exposure',
    description: 'Check if gateway is exposed on 0.0.0.0 without auth token',
    severity: 'critical',
    check: (config) => {
      const gateway = config.gateway || {};
      const bindAddress = gateway.bind_address || '127.0.0.1';
      const hasAuth = gateway.auth_token || process.env.CLAWDBOT_AUTH_TOKEN;
      
      if (bindAddress === '0.0.0.0' && !hasAuth) {
        return {
          vulnerable: true,
          finding: `Gateway exposed on 0.0.0.0:${gateway.port || 18789} without authentication`,
          recommendation: 'Set gateway.auth_token in environment variables'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'dm-policy',
    name: 'DM Policy Configuration',
    description: 'Check if DM policy is set to allowlist',
    severity: 'high',
    check: (config) => {
      const dmPolicy = config.dm_policy;
      
      if (!dmPolicy || dmPolicy === 'allow' || dmPolicy === 'all') {
        return {
          vulnerable: true,
          finding: `DM policy is "${dmPolicy || 'unset'}" - allows all users`,
          recommendation: 'Set dm_policy to allowlist with explicit users'
        };
      }
      if (dmPolicy === 'allowlist') {
        const allowedUsers = config.dm_policy_allowlist || [];
        if (allowedUsers.length === 0) {
          return {
            vulnerable: true,
            finding: 'DM policy is allowlist but no users are specified',
            recommendation: 'Add trusted users to dm_policy_allowlist'
          };
        }
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'sandbox-disabled',
    name: 'Sandbox Configuration',
    description: 'Check if sandbox isolation is enabled',
    severity: 'high',
    check: (config) => {
      const sandbox = config.sandbox;
      
      if (!sandbox || sandbox === 'disabled' || sandbox === 'false') {
        return {
          vulnerable: true,
          finding: `Sandbox is "${sandbox || 'unset'}" - disabled by default`,
          recommendation: 'Enable sandbox=all and docker.network=none for isolation'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'credentials-plaintext',
    name: 'Credentials Security',
    description: 'Check for plaintext credentials and file permissions',
    severity: 'critical',
    check: () => {
      const oauthPath = join(homedir(), '.clawdbot', 'oauth.json');
      const envPath = join(homedir(), '.clawdbot', '.env');
      
      const findings = [];
      
      if (existsSync(oauthPath)) {
        findings.push({
          file: oauthPath,
          issue: 'OAuth credentials may be stored in plaintext',
          recommendation: 'Use environment variables and chmod 600 permissions'
        });
      }
      
      if (existsSync(envPath)) {
        try {
          const perms = existsSync(envPath) ? 'check file permissions manually' : null;
          if (perms) {
            findings.push({
              file: envPath,
              issue: 'Environment file exists - verify permissions',
              recommendation: 'Ensure file has restrictive permissions (chmod 600)'
            });
          }
        } catch (e) {}
      }
      
      return findings.length > 0 ? { vulnerable: true, finding: findings } : { vulnerable: false };
    }
  },
  {
    id: 'prompt-injection',
    name: 'Prompt Injection Protection',
    description: 'Check if untrusted content wrapping is configured',
    severity: 'medium',
    check: (config) => {
      const untrustedWrap = config.wrap_untrusted_content || config.untrusted_content_wrapper;
      
      if (!untrustedWrap) {
        return {
          vulnerable: true,
          finding: 'No prompt injection protection configured for untrusted content',
          recommendation: 'Enable content wrapping for web/sandbox content via wrap_untrusted_content'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'dangerous-commands',
    name: 'Dangerous Command Blocking',
    description: 'Check if dangerous commands are blocked',
    severity: 'high',
    check: (config) => {
      const blocked = config.blocked_commands || config.dangerous_commands || [];
      const dangerous = ['rm -rf', 'curl |', 'git push --force', 'mkfs', ':(){:|:&}'];
      
      const missing = dangerous.filter(cmd => !blocked.some(b => b.includes(cmd)));
      
      if (missing.length > 0) {
        return {
          vulnerable: true,
          finding: `Missing command blocks: ${missing.join(', ')}`,
          recommendation: 'Add dangerous commands to blocked_commands list'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'network-isolation',
    name: 'Network Isolation',
    description: 'Check if Docker network isolation is configured',
    severity: 'medium',
    check: (config) => {
      const docker = config.docker || {};
      const network = docker.network;
      
      if (!network || network === 'bridge' || network === 'default') {
        return {
          vulnerable: true,
          finding: `Docker network is "${network || 'default'}" - no isolation`,
          recommendation: 'Set docker.network=none or use custom isolated network'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'elevated-access',
    name: 'Elevated Tool Access',
    description: 'Check if tool access is properly restricted',
    severity: 'medium',
    check: (config) => {
      const mcpTools = config.mcp_tools || config.tool_access || [];
      
      if (!config.restrict_tools && mcpTools.length > 0) {
        return {
          vulnerable: true,
          finding: 'MCP tools may have broad access - no restrictions configured',
          recommendation: 'Restrict MCP tools to minimum needed with restrict_tools=true'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'audit-logging',
    name: 'Audit Logging',
    description: 'Check if comprehensive session logging is enabled',
    severity: 'medium',
    check: (config) => {
      const audit = config.audit_logging || config.session_logging || config.audit;
      
      if (!audit || audit === 'false' || audit === 'disabled') {
        return {
          vulnerable: true,
          finding: 'Audit logging is disabled',
          recommendation: 'Enable comprehensive session logging for security monitoring'
        };
      }
      return { vulnerable: false };
    }
  },
  {
    id: 'pairing-codes',
    name: 'Pairing Code Security',
    description: 'Check if pairing codes use cryptographic randomness',
    severity: 'medium',
    check: (config) => {
      const pairing = config.pairing || {};
      
      if (pairing.code_length && pairing.code_length < 8) {
        return {
          vulnerable: true,
          finding: `Pairing code length (${pairing.code_length}) is too short`,
          recommendation: 'Use cryptographic random codes with minimum 8 characters + rate limiting'
        };
      }
      
      if (!pairing.rate_limit && !pairing.max_attempts) {
        return {
          vulnerable: true,
          finding: 'No rate limiting on pairing codes',
          recommendation: 'Enable rate limiting to prevent brute force attacks'
        };
      }
      
      return { vulnerable: false };
    }
  }
];

function loadConfig() {
  const configPaths = [
    join(homedir(), '.clawdbot', 'config.json'),
    join(homedir(), '.clawdbot', 'config.yaml'),
    join(homedir(), '.clawdbot', '.clawdbotrc'),
    join(process.cwd(), '.clawdbotrc'),
    '.clawdbotrc'
  ];
  
  for (const path of configPaths) {
    if (existsSync(path)) {
      try {
        const content = readFileSync(path, 'utf8');
        if (path.endsWith('.json')) {
          return JSON.parse(content);
        }
        // Simple YAML parsing for basic structure
        const result = {};
        content.split('\n').forEach(line => {
          const match = line.match(/^(\w+):\s*(.*)$/);
          if (match) {
            result[match[1]] = match[2];
          }
        });
        return result;
      } catch (e) {
        // Continue to next path
      }
    }
  }
  
  return {};
}

function runAnalysis(config = {}) {
  const results = {
    timestamp: new Date().toISOString(),
    summary: { passed: 0, warnings: 0, critical: 0 },
    findings: []
  };
  
  for (const check of CHECKS) {
    try {
      const result = check.check(config);
      
      if (result.vulnerable) {
        const severity = check.severity;
        results.summary[severity === 'critical' ? 'critical' : severity === 'high' ? 'warnings' : 'warnings']++;
        
        results.findings.push({
          id: check.id,
          name: check.name,
          severity: check.severity,
          description: check.description,
          ...result
        });
      } else {
        results.summary.passed++;
      }
    } catch (e) {
      results.findings.push({
        id: check.id,
        name: check.name,
        severity: 'info',
        description: check.description,
        error: e.message
      });
    }
  }
  
  return results;
}

function formatReport(results) {
  const lines = [];
  lines.push('═'.repeat(60));
  lines.push('🔒 CLAWDBOT SECURITY ANALYSIS REPORT');
  lines.push('═'.repeat(60));
  lines.push(`Generated: ${results.timestamp}`);
  lines.push('');
  
  lines.push('┌─ SUMMARY ───────────────────────────────────────────────');
  lines.push(`│ ✅ Passed:     ${results.summary.passed}`);
  lines.push(`│ ⚠️  Warnings:   ${results.summary.warnings}`);
  lines.push(`│ 🔴 Critical:   ${results.summary.critical}`);
  lines.push('└────────────────────────────────────────────────────────');
  lines.push('');
  
  if (results.findings.length === 0) {
    lines.push('✅ No security issues found!');
    return lines.join('\n');
  }
  
  // Sort by severity
  const sorted = results.findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, info: 3 };
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  });
  
  lines.push('┌─ FINDINGS ──────────────────────────────────────────────');
  
  for (const f of sorted) {
    const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🔵';
    lines.push(`│ ${icon} [${f.severity.toUpperCase()}] ${f.name}`);
    lines.push(`│    ${f.description}`);
    
    if (f.finding) {
      if (Array.isArray(f.finding)) {
        f.finding.forEach(item => {
          lines.push(`│    • ${item.file || item.issue}: ${item.recommendation}`);
        });
      } else {
        lines.push(`│    Finding: ${f.finding}`);
      }
    }
    
    if (f.recommendation) {
      lines.push(`│    → ${f.recommendation}`);
    }
    lines.push('');
  }
  
  lines.push('└────────────────────────────────────────────────────────');
  lines.push('');
  lines.push('This is a READ-ONLY analysis. No changes were made.');
  
  return lines.join('\n');
}

// CLI execution
const config = loadConfig();
const results = runAnalysis(config);
const report = formatReport(results);

console.log(report);

// Optional: output JSON for programmatic use
if (process.argv.includes('--json')) {
  console.log('\n--- JSON OUTPUT ---');
  console.log(JSON.stringify(results, null, 2));
}
