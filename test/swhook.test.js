'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const { scanContent, scanProject } = require('../bin/swhook.js');

const EXAMPLES = path.join(__dirname, '..', 'examples');

test('broken webhook triggers NO_SIGNATURE_CHECK and HARDCODED_WEBHOOK_SECRET', () => {
  const res = scanProject(path.join(EXAMPLES, 'broken'));
  const rules = res.findings.map((f) => f.rule);
  assert.ok(rules.includes('NO_SIGNATURE_CHECK'));
  assert.ok(rules.includes('HARDCODED_WEBHOOK_SECRET'));
  assert.ok(res.findings.find((f) => f.rule === 'NO_SIGNATURE_CHECK').severity === 'critical');
});

test('clean webhook (constructEvent + env secret + raw body) produces zero findings', () => {
  const res = scanProject(path.join(EXAMPLES, 'clean'));
  assert.strictEqual(res.findings.length, 0);
});

test('constructEvent present but secret source invisible flags low', () => {
  const findings = scanContent('// stripe webhook route\nconst e = stripe.webhooks.constructEvent(raw, sig, secret);\n', 'w.js');
  assert.ok(findings.some((f) => f.rule === 'SECRET_SOURCE_UNKNOWN' && f.severity === 'low'));
});

test('body parser + verified webhook flags the raw-body hint', () => {
  const findings = scanContent('router.post("/stripe/webhook", express.json(), (req,res)=>{ const e = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); res.json({received:true}); });', 'w.js');
  assert.ok(findings.some((f) => f.rule === 'BODY_PARSER_BEFORE_WEBHOOK' && f.severity === 'medium'));
});

test('files without stripe or webhook are never flagged', () => {
  const findings = scanContent('router.post("/health", express.json(), (req,res)=>{ const x = JSON.parse(req.body); res.json(x); });', 'h.js');
  assert.strictEqual(findings.length, 0);
});

test('evidence never contains the full whsec token', () => {
  const res = scanProject(path.join(EXAMPLES, 'broken'));
  for (const f of res.findings) {
    assert.ok(!f.evidence.includes('FAKE0000FAKE0000'), 'secret leaked in evidence');
  }
});
