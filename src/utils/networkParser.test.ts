import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateCvssV31,
  classifyPortRisk,
  diffScans,
  generateAssessmentMarkdown,
  isIpInCidr,
  parseNmapOutput,
  validateTargetInScope,
} from './networkParser';

test('isIpInCidr accurately evaluates IPv4 subnet boundaries', () => {
  assert.equal(isIpInCidr('10.20.10.10', '10.20.0.0/16'), true);
  assert.equal(isIpInCidr('10.20.99.5', '10.20.99.0/24'), true);
  assert.equal(isIpInCidr('10.21.10.10', '10.20.0.0/16'), false);
  assert.equal(isIpInCidr('8.8.8.8', '10.20.0.0/16'), false);
});

test('validateTargetInScope blocks out-of-scope and malformed IPs while mapping authorized VLANs', () => {
  const empty = validateTargetInScope('   ');
  assert.equal(empty.valid, false);
  assert.equal(empty.inScope, false);

  const malformed = validateTargetInScope('10.20.999.1');
  assert.equal(malformed.valid, false);
  assert.equal(malformed.inScope, false);

  const external = validateTargetInScope('8.8.8.8');
  assert.equal(external.valid, true);
  assert.equal(external.inScope, false);
  assert.match(external.message, /HORS PÉRIMÈTRE BLOQUÉ/);

  const dmz = validateTargetInScope('10.20.10.12');
  assert.equal(dmz.valid, true);
  assert.equal(dmz.inScope, true);
  assert.equal(dmz.matchedVlan?.id, 'vlan-10');
});

test('parseNmapOutput parses standard and grepable Nmap outputs and skips out-of-scope targets', () => {
  const sample = `
Nmap scan report for edge-gw.lab (10.20.10.10)
Host is up (0.0012s latency).
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1
80/tcp  open  http     nginx 1.24.0
443/tcp open  ssl/http nginx 1.24.0

Nmap scan report for public-dns (8.8.8.8)
Host is up (0.014s latency).
PORT   STATE SERVICE
53/tcp open  domain
`;
  const parsed = parseNmapOutput(sample);
  assert.equal(parsed.valid, true);
  assert.equal(parsed.hosts.length, 1);
  assert.equal(parsed.hosts[0].ip, '10.20.10.10');
  assert.equal(parsed.hosts[0].ports.length, 3);
  assert.deepEqual(parsed.outOfScopeIps, ['8.8.8.8']);
  assert.equal(parsed.totalOpenPorts, 3);
});

test('parseNmapOutput handles empty, malformed, and host-down edge cases cleanly', () => {
  const empty = parseNmapOutput('');
  assert.equal(empty.valid, false);

  const garbage = parseNmapOutput('texte aléatoire invalide');
  assert.equal(garbage.valid, false);
  assert.match(garbage.error ?? '', /Format de scan non reconnu/);

  const hostDown = parseNmapOutput(`
Nmap scan report for 10.20.30.99
Note: Host seems down. If it is really up, try -Pn.
`);
  assert.equal(hostDown.valid, true);
  assert.equal(hostDown.hosts[0].hostState, 'down');
  assert.equal(hostDown.totalOpenPorts, 0);
});

test('diffScans computes port closure and reduction percentage accurately', () => {
  const base = parseNmapOutput(`
Nmap scan report for app-01 (10.20.20.14)
PORT     STATE SERVICE VERSION
23/tcp   open  telnet  Linux telnetd
80/tcp   open  http    Apache 2.4
6379/tcp open  redis   Redis 7.0
`);
  const retest = parseNmapOutput(`
Nmap scan report for app-01 (10.20.20.14)
PORT    STATE  SERVICE VERSION
23/tcp  closed telnet
80/tcp  closed http
443/tcp open   https   nginx 1.24
`);
  const diff = diffScans(base, retest);
  assert.equal(diff.baselineOpenCount, 3);
  assert.equal(diff.retestOpenCount, 1);
  assert.equal(diff.closedPorts.length, 3);
  assert.equal(diff.newlyOpenedPorts.length, 1);
  assert.equal(diff.reductionPercent, 67);
});

test('classifyPortRisk and calculateCvssV31 produce accurate severity ratings', () => {
  const telnetRisk = classifyPortRisk(23, 'open', 'telnet', 'Linux telnetd');
  assert.equal(telnetRisk.riskLevel, 'Critical');

  const redisUnauth = classifyPortRisk(6379, 'open', 'redis', 'Redis key-value store 7.0.11 (unauthenticated)');
  assert.equal(redisUnauth.riskLevel, 'Critical');

  const httpsRisk = classifyPortRisk(443, 'open', 'https', 'nginx');
  assert.equal(httpsRisk.riskLevel, 'Nominal');

  const crit = calculateCvssV31({
    AV: 'N',
    AC: 'L',
    PR: 'N',
    UI: 'N',
    S: 'C',
    C: 'H',
    I: 'H',
    A: 'N',
  });
  assert.equal(crit.severity, 'Critical');
  assert.equal(crit.score, 10.0);

  const med = calculateCvssV31({
    AV: 'N',
    AC: 'H',
    PR: 'L',
    UI: 'N',
    S: 'U',
    C: 'L',
    I: 'L',
    A: 'N',
  });
  assert.equal(med.severity, 'Medium');
  assert.ok(med.score >= 4.0 && med.score < 7.0);
});

test('generateAssessmentMarkdown includes scope, findings, and diff summary in French', () => {
  const md = generateAssessmentMarkdown({
    vlans: [
      {
        id: 'vlan-10',
        vlanTag: 10,
        name: 'VLAN 10 · Zone DMZ',
        cidr: '10.20.10.0/24',
        purpose: 'Entrée',
        gateway: '10.20.10.1',
        trustZone: 'Untrusted',
      },
    ],
    findings: [],
    artifacts: [],
    diff: {
      closedPorts: [],
      persistingOpenPorts: [],
      newlyOpenedPorts: [],
      baselineOpenCount: 10,
      retestOpenCount: 2,
      reductionPercent: 80,
    },
    generatedDate: '2026-11-17',
  });
  assert.match(md, /10\.20\.0\.0\/16/);
  assert.match(md, /-80%/);
  assert.match(md, /Rapport d’Audit/);
});
