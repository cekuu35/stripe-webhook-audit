#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const SOURCE_EXT = new Set(['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const STRIPE_RE = /stripe/i;
const WEBHOOK_RE = /webhook/i;
const CONSTRUCT_RE = /stripe\.webhooks\.constructEvent(Async)?|constructEvent(Async)?\s*\(/;
const JSON_PARSE_BODY_RE = /JSON\.parse\s*\(\s*(req\.body|request\.body|event\.body|ctx\.req\.body|body)\b/;
const WHSEC_RE = /whsec_[A-Za-z0-9]{16,}/;
const EXPRESSION_SECRET_RE = /process\.env\.[A-Z_]*WEBHOOK_?SECRET|env\.WEBHOOK_SECRET/;

function redact(value) {
  const v = String(value);
  if (v.length <= 8) return v.slice(0, 2) + '***';
  return v.slice(0, 6) + '***(' + v.length + ' chars)';
}

function scanContent(content, filePath) {
  if (!STRIPE_RE.test(content) || !WEBHOOK_RE.test(content)) return [];
  const findings = [];
  const isWebhookFile = WEBHOOK_RE.test(content) && STRIPE_RE.test(content);
  if (!isWebhookFile) return findings;

  if (WHSEC_RE.test(content)) {
    const m = WHSEC_RE.exec(content);
    if (!EXPRESSION_SECRET_RE.test(content)) {
      findings.push({
        rule: 'HARDCODED_WEBHOOK_SECRET', severity: 'high',
        detail: 'a Stripe webhook signing secret (whsec_...) is hardcoded — move it to an environment variable; rotate it if it was ever committed',
        evidence: redact(m[0]),
      });
    }
  }

  const verifies = CONSTRUCT_RE.test(content);
  if (!verifies) {
    if (JSON_PARSE_BODY_RE.test(content)) {
      findings.push({
        rule: 'NO_SIGNATURE_CHECK', severity: 'critical',
        detail: 'this file handles Stripe webhook events via JSON.parse on the raw body without any signature verification — anyone who finds the URL can forge events (charges, refunds, subscription changes)',
        evidence: 'JSON.parse(body) + no constructEvent',
      });
    } else {
      findings.push({
        rule: 'NO_SIGNATURE_CHECK', severity: 'critical',
        detail: 'Stripe webhook handler with no constructEvent call — events are trusted without verifying they came from Stripe',
        evidence: 'stripe + webhook route, no constructEvent',
      });
    }
  }

  const rawBodyHint = /express\.json|bodyParser\.json|app\.use\(.*json/i.test(content) && /webhook/i.test(content);
  if (verifies && rawBodyHint) {
    findings.push({
      rule: 'BODY_PARSER_BEFORE_WEBHOOK', severity: 'medium',
      detail: 'a JSON body parser and a Stripe webhook handler coexist in this file — constructEvent needs the RAW body; a parsed body makes verification fail (and tempts people to remove it)',
      evidence: 'express/bodyParser json + webhook route',
    });
  }

  if (verifies && !EXPRESSION_SECRET_RE.test(content) && !WHSEC_RE.test(content)) {
    findings.push({
      rule: 'SECRET_SOURCE_UNKNOWN', severity: 'low',
      detail: 'signature verification present but no visible secret source (no env reference, no literal) — confirm the signing secret comes from configuration, not from something committed elsewhere',
      evidence: 'constructEvent without a discoverable secret source in this file',
    });
  }

  return findings;
}

function walk(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
}

function scanProject(root) {
  const findings = [];
  const files = [];
  walk(root, files);
  let scanned = 0;
  for (const f of files) {
    if (!SOURCE_EXT.has(path.extname(f))) continue;
    scanned++;
    let raw;
    try {
      raw = fs.readFileSync(f, 'utf8');
    } catch {
      continue;
    }
    const found = scanContent(raw, f);
    for (const x of found) findings.push({ file: f, ...x });
  }
  return { root, sourceFiles: scanned, findings };
}

function printReport(results) {
  const lines = [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const res of results) {
    lines.push('');
    lines.push('== ' + res.root + ' (' + res.sourceFiles + ' source files scanned)');
    for (const f of res.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      lines.push('   [' + f.severity.toUpperCase() + '] ' + f.rule + ' - ' + path.relative(res.root, f.file));
      lines.push('       ' + f.detail);
      lines.push('       evidence: ' + f.evidence);
    }
  }
  return { text: lines.join('\n'), counts };
}

function main(argv) {
  const json = argv.includes('--json');
  const roots = argv.filter((a) => !a.startsWith('--'));
  const targets = roots.length > 0 ? roots : [process.cwd()];
  const results = targets.map((r) => scanProject(r));
  if (json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    const { text, counts } = printReport(results);
    console.log(text);
    console.log('');
    console.log('Summary: ' + counts.critical + ' critical, ' + counts.high + ' high, ' + counts.medium + ' medium, ' + counts.low + ' low');
  }
  const blocking = results.some((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high'));
  return blocking ? 1 : 0;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { scanContent, scanProject, redact, main };
