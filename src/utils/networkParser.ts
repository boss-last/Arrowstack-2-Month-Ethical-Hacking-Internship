import type {
  CvssMetrics,
  EvidenceArtifact,
  Finding,
  FindingStatus,
  NmapParseResult,
  ParsedHostResult,
  ParsedPort,
  ScanDiffSummary,
  ScopeValidationResult,
  Severity,
  VlanSegment,
} from '../types/assessment';

export const AUTHORIZED_ROOT_CIDR = '10.20.0.0/16';

export function formatSeverityFr(severity: Severity | 'Nominal'): string {
  switch (severity) {
    case 'Critical':
      return 'Critique';
    case 'High':
      return 'Élevée';
    case 'Medium':
      return 'Moyenne';
    case 'Low':
      return 'Faible';
    case 'Informational':
      return 'Informationnelle';
    default:
      return 'Nominale';
  }
}

export function formatStatusFr(status: FindingStatus): string {
  switch (status) {
    case 'Open':
      return 'Ouverte';
    case 'Remediated':
      return 'Corrigée';
    case 'Accepted Risk':
      return 'Risque accepté';
  }
}

export function formatCategoryFr(category: Finding['category']): string {
  switch (category) {
    case 'Exposed Service':
      return 'Service exposé';
    case 'Weak Configuration':
      return 'Configuration faible';
    case 'Segmentation Gap':
      return 'Faille de segmentation';
    case 'Cleartext Traffic':
      return 'Trafic en clair';
  }
}

export const DEFAULT_LAB_VLANS: VlanSegment[] = [
  {
    id: 'vlan-10',
    vlanTag: 10,
    name: 'VLAN 10 · Zone DMZ',
    cidr: '10.20.10.0/24',
    purpose: 'Reverse proxy exposé et passerelle d’entrée',
    gateway: '10.20.10.1',
    trustZone: 'Untrusted',
  },
  {
    id: 'vlan-20',
    vlanTag: 20,
    name: 'VLAN 20 · Tier Applicatif',
    cidr: '10.20.20.0/24',
    purpose: 'API internes, cache de session et workers applicatifs',
    gateway: '10.20.20.1',
    trustZone: 'Semi-Trusted',
  },
  {
    id: 'vlan-30',
    vlanTag: 30,
    name: 'VLAN 30 · Données & Stockage',
    cidr: '10.20.30.0/24',
    purpose: 'Base de données relationnelle et partage SMB interne',
    gateway: '10.20.30.1',
    trustZone: 'Restricted',
  },
  {
    id: 'vlan-99',
    vlanTag: 99,
    name: 'VLAN 99 · Administration',
    cidr: '10.20.99.0/24',
    purpose: 'Bastion de rebond, pare-feu et collecteur syslog',
    gateway: '10.20.99.1',
    trustZone: 'Isolated Admin',
  },
];

export function formatTrustZoneFr(zone: VlanSegment['trustZone']): string {
  switch (zone) {
    case 'Untrusted':
      return 'Non fiable';
    case 'Semi-Trusted':
      return 'Confiance partielle';
    case 'Restricted':
      return 'Restreinte';
    case 'Isolated Admin':
      return 'Admin isolée';
  }
}

export function ipv4ToInt(ip: string): number | null {
  const trimmed = ip.trim();
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(trimmed);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  if (octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) return null;
  return (
    ((octets[0] << 24) >>> 0) +
    ((octets[1] << 16) >>> 0) +
    ((octets[2] << 8) >>> 0) +
    (octets[3] >>> 0)
  ) >>> 0;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const [networkStr, prefixStr] = cidr.trim().split('/');
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(networkStr ?? '');
  const prefix = Number(prefixStr);
  if (ipInt === null || netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

export function validateTargetInScope(
  input: string,
  vlans: VlanSegment[] = DEFAULT_LAB_VLANS,
  allowedCidrs: string[] = [AUTHORIZED_ROOT_CIDR],
): ScopeValidationResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return {
      valid: false,
      inScope: false,
      normalizedIp: '',
      matchedVlan: null,
      message: 'Saisissez une adresse IPv4 (par exemple 10.20.20.14) pour vérifier le périmètre.',
    };
  }

  const ipCandidate = trimmed.includes('/') ? trimmed.split('/')[0] : trimmed;
  if (trimmed.includes('/')) {
    const prefix = Number(trimmed.split('/')[1]);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return {
        valid: false,
        inScope: false,
        normalizedIp: trimmed,
        matchedVlan: null,
        message: `Préfixe CIDR invalide « ${trimmed} ». Indiquez une adresse IPv4 ou un bloc CIDR valide.`,
      };
    }
  }

  const ipInt = ipv4ToInt(ipCandidate);
  if (ipInt === null) {
    return {
      valid: false,
      inScope: false,
      normalizedIp: trimmed,
      matchedVlan: null,
      message: `Adresse IPv4 malformée « ${trimmed} ». Chaque octet doit être compris entre 0 et 255.`,
    };
  }

  const withinAuthorizedRoot = allowedCidrs.some((cidr) => isIpInCidr(ipCandidate, cidr));
  if (!withinAuthorizedRoot) {
    return {
      valid: true,
      inScope: false,
      normalizedIp: ipCandidate,
      matchedVlan: null,
      message: `HORS PÉRIMÈTRE BLOQUÉ : ${ipCandidate} se situe hors du laboratoire autorisé (${allowedCidrs.join(', ')}). L’analyse d’adresses publiques ou de production est interdite.`,
    };
  }

  const matchedVlan = vlans.find((v) => isIpInCidr(ipCandidate, v.cidr)) ?? null;
  return {
    valid: true,
    inScope: true,
    normalizedIp: ipCandidate,
    matchedVlan,
    message: matchedVlan
      ? `Cible autorisée rattachée à ${matchedVlan.name} (${formatTrustZoneFr(matchedVlan.trustZone)}).`
      : `Cible autorisée dans ${allowedCidrs.join(', ')}, segment VLAN non alloué.`,
  };
}

export function classifyPortRisk(
  port: number,
  state: ParsedPort['state'],
  service: string,
  version: string,
): { riskLevel: Severity | 'Nominal'; riskNote: string } {
  if (state !== 'open' && state !== 'open|filtered') {
    return { riskLevel: 'Nominal', riskNote: `Port ${state} ; aucun service actif joignable.` };
  }

  const svcLower = service.toLowerCase();
  const verLower = version.toLowerCase();

  if (port === 23 || svcLower.includes('telnet')) {
    return {
      riskLevel: 'Critical',
      riskNote: 'Le démon Telnet en clair expose les identifiants d’administration sur le réseau.',
    };
  }
  if (port === 6379 || svcLower.includes('redis')) {
    if (
      !verLower.includes('unauthenticated') &&
      (verLower.includes('requirepass') || verLower.includes('auth enabled') || verLower.includes('protected'))
    ) {
      return {
        riskLevel: 'Low',
        riskNote: 'Instance Redis détectée avec indice d’authentification ; vérifier l’adresse d’écoute.',
      };
    }
    return {
      riskLevel: 'Critical',
      riskNote: 'Service Redis sans authentification exposé sur le réseau (lecture/écriture et RCE possibles).',
    };
  }
  if (port === 445 || svcLower.includes('microsoft-ds') || svcLower.includes('smb')) {
    return {
      riskLevel: 'High',
      riskNote: 'Partage SMB exposé entre VLAN ; vérifier la désactivation de SMBv1 et les ACL.',
    };
  }
  if (port === 21 || svcLower === 'ftp') {
    return {
      riskLevel: 'High',
      riskNote: 'Canal FTP non chiffré exposant les identifiants en transit.',
    };
  }
  if (port === 3306 || svcLower.includes('mysql') || port === 5432 || svcLower.includes('postgresql')) {
    return {
      riskLevel: 'High',
      riskNote: 'Port de base de données joignable sans ACL stricte ; restreindre au VLAN 20 applicatif.',
    };
  }
  if (port === 80 || svcLower === 'http') {
    return {
      riskLevel: 'Medium',
      riskNote: 'Service HTTP en clair actif sans redirection HTTPS forcée ni en-tête HSTS.',
    };
  }
  if (port === 161 || svcLower.includes('snmp')) {
    return {
      riskLevel: 'Medium',
      riskNote: 'Agent SNMP exposé ; exiger SNMPv3 authPriv et supprimer les communautés par défaut.',
    };
  }
  if (port === 22 || svcLower === 'ssh') {
    if (verLower.includes('openssh 7.') || verLower.includes('password')) {
      return {
        riskLevel: 'Medium',
        riskNote: 'SSH exposé ; imposer l’authentification par clé et limiter l’accès au bastion VLAN 99.',
      };
    }
    return {
      riskLevel: 'Low',
      riskNote: 'Port d’administration SSH ; vérifier que l’ACL limite la source au bastion VLAN 99.',
    };
  }
  if (port === 443 || svcLower === 'https' || svcLower === 'ssl/http') {
    return {
      riskLevel: 'Nominal',
      riskNote: 'Point d’entrée HTTPS chiffré.',
    };
  }

  return {
    riskLevel: 'Low',
    riskNote: `Service ${service || 'inconnu'} ouvert sur le port ${port} ; vérifier la justification métier.`,
  };
}

export function parseNmapOutput(
  raw: string,
  vlans: VlanSegment[] = DEFAULT_LAB_VLANS,
  allowedCidrs: string[] = [AUTHORIZED_ROOT_CIDR],
): NmapParseResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return {
      valid: false,
      error: 'Saisie vide. Collez une sortie Nmap standard ou grepable (-oG) pour lancer l’analyse.',
      warnings: [],
      hosts: [],
      totalOpenPorts: 0,
      flaggedRiskPorts: 0,
      outOfScopeIps: [],
    };
  }

  const lines = trimmed.split(/\r?\n/);
  const hosts: ParsedHostResult[] = [];
  const warnings: string[] = [];
  const outOfScopeIps: string[] = [];

  let currentHost: ParsedHostResult | null = null;
  let inPortTable = false;

  const commitHost = (host: ParsedHostResult | null) => {
    if (!host) return;
    const existing = hosts.find((h) => h.ip === host.ip);
    if (existing) {
      for (const p of host.ports) {
        if (!existing.ports.some((ep) => ep.port === p.port && ep.protocol === p.protocol)) {
          existing.ports.push(p);
        }
      }
      if (host.hostState === 'up') existing.hostState = 'up';
    } else {
      hosts.push(host);
    }
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      inPortTable = false;
      continue;
    }

    if (line.startsWith('Host:') && line.includes('Ports:')) {
      const hostMatch = /^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s*(?:\(([^)]*)\))?/.exec(line);
      if (hostMatch) {
        const ip = hostMatch[1];
        const hostname = hostMatch[2]?.trim() || ip;
        const scopeCheck = validateTargetInScope(ip, vlans, allowedCidrs);
        if (!scopeCheck.inScope) {
          outOfScopeIps.push(ip);
          warnings.push(`Hôte hors périmètre ignoré : ${ip}`);
          continue;
        }
        const parsedHost: ParsedHostResult = {
          ip,
          hostname,
          vlanMatch: scopeCheck.matchedVlan?.name ?? 'Lab autorisé',
          inScope: true,
          hostState: 'up',
          ports: [],
        };
        const portsSegment = line.split('Ports:')[1]?.split('Ignored State:')[0] ?? '';
        const entries = portsSegment.split(',').map((s) => s.trim()).filter(Boolean);
        for (const entry of entries) {
          const parts = entry.split('/');
          const portNum = Number(parts[0]);
          const stateRaw = parts[1] as ParsedPort['state'];
          const proto = (parts[2] === 'udp' ? 'udp' : 'tcp') as 'tcp' | 'udp';
          const service = parts[4] || 'inconnu';
          const version = parts[6] || '';
          if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) continue;
          const { riskLevel, riskNote } = classifyPortRisk(portNum, stateRaw, service, version);
          parsedHost.ports.push({
            port: portNum,
            protocol: proto,
            state: stateRaw,
            service,
            version,
            riskLevel,
            riskNote,
          });
        }
        commitHost(parsedHost);
        continue;
      }
    }

    const reportMatch = /^Nmap scan report for\s+(.+)$/i.exec(line);
    if (reportMatch) {
      commitHost(currentHost);
      inPortTable = false;
      const targetText = reportMatch[1].trim();
      const parenIpMatch = /^([^\s(]+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)$/.exec(targetText);
      const bareIpMatch = /^(\d{1,3}(?:\.\d{1,3}){3})$/.exec(targetText);

      const ip = parenIpMatch ? parenIpMatch[2] : bareIpMatch ? bareIpMatch[1] : '';
      const hostname = parenIpMatch ? parenIpMatch[1] : targetText;

      if (!ip) {
        warnings.push(`L’hôte « ${targetText} » ne comporte pas d’adresse IPv4 résolue et a été ignoré.`);
        currentHost = null;
        continue;
      }

      const scopeCheck = validateTargetInScope(ip, vlans, allowedCidrs);
      if (!scopeCheck.inScope) {
        outOfScopeIps.push(ip);
        warnings.push(`Le garde-fou de périmètre a bloqué la cible non autorisée ${ip}.`);
        currentHost = null;
        continue;
      }

      currentHost = {
        ip,
        hostname,
        vlanMatch: scopeCheck.matchedVlan?.name ?? 'Lab autorisé',
        inScope: true,
        hostState: 'up',
        ports: [],
      };
      continue;
    }

    if (!currentHost) continue;

    if (/Host seems down/i.test(line)) {
      currentHost.hostState = 'down';
      warnings.push(`L’hôte ${currentHost.ip} est signalé injoignable ou bloque les sondes ICMP/SYN.`);
      continue;
    }

    if (/All \d+ scanned ports on .+ are (?:in ignored states|filtered)/i.test(line)) {
      currentHost.hostState = 'filtered';
      continue;
    }

    if (/^PORT\s+STATE\s+SERVICE/i.test(line)) {
      inPortTable = true;
      continue;
    }

    if (inPortTable || /^\d+\/(tcp|udp)\s+/.test(line)) {
      const portMatch = /^(\d+)\/(tcp|udp)\s+(open\|filtered|open|filtered|closed)\s+(\S+)(?:\s+(.*))?$/i.exec(line);
      if (portMatch) {
        const portNum = Number(portMatch[1]);
        const protocol = portMatch[2].toLowerCase() as 'tcp' | 'udp';
        const state = portMatch[3].toLowerCase() as ParsedPort['state'];
        const service = portMatch[4];
        const version = (portMatch[5] ?? '').trim();

        if (portNum >= 1 && portNum <= 65535) {
          if (!currentHost.ports.some((p) => p.port === portNum && p.protocol === protocol)) {
            const { riskLevel, riskNote } = classifyPortRisk(portNum, state, service, version);
            currentHost.ports.push({
              port: portNum,
              protocol,
              state,
              service,
              version,
              riskLevel,
              riskNote,
            });
          }
        }
      }
    }
  }

  commitHost(currentHost);

  if (hosts.length === 0 && outOfScopeIps.length > 0) {
    return {
      valid: false,
      error: `Toutes les cibles (${outOfScopeIps.join(', ')}) sont hors du bloc autorisé ${allowedCidrs.join(', ')} et ont été bloquées.`,
      warnings,
      hosts: [],
      totalOpenPorts: 0,
      flaggedRiskPorts: 0,
      outOfScopeIps,
    };
  }

  if (hosts.length === 0) {
    return {
      valid: false,
      error: 'Format de scan non reconnu. Collez une sortie Nmap standard (« Nmap scan report for... ») ou grepable (-oG).',
      warnings,
      hosts: [],
      totalOpenPorts: 0,
      flaggedRiskPorts: 0,
      outOfScopeIps,
    };
  }

  const totalOpenPorts = hosts.reduce(
    (sum, h) => sum + h.ports.filter((p) => p.state === 'open' || p.state === 'open|filtered').length,
    0,
  );
  const flaggedRiskPorts = hosts.reduce(
    (sum, h) =>
      sum +
      h.ports.filter(
        (p) =>
          (p.state === 'open' || p.state === 'open|filtered') &&
          (p.riskLevel === 'Critical' || p.riskLevel === 'High' || p.riskLevel === 'Medium'),
      ).length,
    0,
  );

  return {
    valid: true,
    error: null,
    warnings,
    hosts,
    totalOpenPorts,
    flaggedRiskPorts,
    outOfScopeIps,
  };
}

export function diffScans(baseline: NmapParseResult, retest: NmapParseResult): ScanDiffSummary {
  const baseMap = new Map<string, { ip: string; port: number; service: string }>();
  for (const h of baseline.hosts) {
    for (const p of h.ports) {
      if (p.state === 'open' || p.state === 'open|filtered') {
        baseMap.set(`${h.ip}:${p.port}/${p.protocol}`, { ip: h.ip, port: p.port, service: p.service });
      }
    }
  }

  const retMap = new Map<string, { ip: string; port: number; service: string }>();
  for (const h of retest.hosts) {
    for (const p of h.ports) {
      if (p.state === 'open' || p.state === 'open|filtered') {
        retMap.set(`${h.ip}:${p.port}/${p.protocol}`, { ip: h.ip, port: p.port, service: p.service });
      }
    }
  }

  const closedPorts: Array<{ ip: string; port: number; service: string }> = [];
  const persistingOpenPorts: Array<{ ip: string; port: number; service: string }> = [];
  const newlyOpenedPorts: Array<{ ip: string; port: number; service: string }> = [];

  for (const [key, item] of baseMap.entries()) {
    if (retMap.has(key)) {
      persistingOpenPorts.push(item);
    } else {
      closedPorts.push(item);
    }
  }

  for (const [key, item] of retMap.entries()) {
    if (!baseMap.has(key)) {
      newlyOpenedPorts.push(item);
    }
  }

  const baselineOpenCount = baseMap.size;
  const retestOpenCount = retMap.size;
  const reductionPercent =
    baselineOpenCount > 0
      ? Math.round(((baselineOpenCount - retestOpenCount) / baselineOpenCount) * 100)
      : 0;

  return {
    closedPorts,
    persistingOpenPorts,
    newlyOpenedPorts,
    baselineOpenCount,
    retestOpenCount,
    reductionPercent,
  };
}

function roundUp1Decimal(val: number): number {
  return Math.ceil(val * 10) / 10;
}

export function calculateCvssV31(metrics: CvssMetrics): {
  score: number;
  severity: Severity;
  vector: string;
} {
  const avWeights: Record<CvssMetrics['AV'], number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const acWeights: Record<CvssMetrics['AC'], number> = { L: 0.77, H: 0.44 };
  const prWeightsUnchanged: Record<CvssMetrics['PR'], number> = { N: 0.85, L: 0.62, H: 0.27 };
  const prWeightsChanged: Record<CvssMetrics['PR'], number> = { N: 0.85, L: 0.68, H: 0.5 };
  const uiWeights: Record<CvssMetrics['UI'], number> = { N: 0.85, R: 0.62 };
  const ciaWeights: Record<'H' | 'L' | 'N', number> = { H: 0.56, L: 0.22, N: 0 };

  const prWeight =
    metrics.S === 'C' ? prWeightsChanged[metrics.PR] : prWeightsUnchanged[metrics.PR];
  const exploitability =
    8.22 * avWeights[metrics.AV] * acWeights[metrics.AC] * prWeight * uiWeights[metrics.UI];

  const iscBase =
    1 - (1 - ciaWeights[metrics.C]) * (1 - ciaWeights[metrics.I]) * (1 - ciaWeights[metrics.A]);

  const impact =
    metrics.S === 'U'
      ? 6.42 * iscBase
      : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  let score = 0;
  if (impact > 0) {
    if (metrics.S === 'U') {
      score = roundUp1Decimal(Math.min(impact + exploitability, 10));
    } else {
      score = roundUp1Decimal(Math.min(1.08 * (impact + exploitability), 10));
    }
  }

  let severity: Severity = 'Informational';
  if (score >= 9.0) severity = 'Critical';
  else if (score >= 7.0) severity = 'High';
  else if (score >= 4.0) severity = 'Medium';
  else if (score >= 0.1) severity = 'Low';

  const vector = `CVSS:3.1/AV:${metrics.AV}/AC:${metrics.AC}/PR:${metrics.PR}/UI:${metrics.UI}/S:${metrics.S}/C:${metrics.C}/I:${metrics.I}/A:${metrics.A}`;

  return { score, severity, vector };
}

export function generateAssessmentMarkdown(params: {
  vlans: VlanSegment[];
  findings: Finding[];
  artifacts: EvidenceArtifact[];
  diff: ScanDiffSummary;
  generatedDate: string;
}): string {
  const { vlans, findings, artifacts, diff, generatedDate } = params;
  const openFindings = findings.filter((f) => f.status === 'Open');
  const remediatedFindings = findings.filter((f) => f.status === 'Remediated');

  const lines: string[] = [
    '# Rapport d’Audit de Sécurité Réseau — Laboratoire Isolé',
    '',
    `- **Date du rapport :** ${generatedDate}`,
    `- **Périmètre autorisé :** ${AUTHORIZED_ROOT_CIDR} (Réseau de laboratoire isolé uniquement)`,
    '- **Partie prenante principale :** Responsable Infrastructure & SecOps',
    '- **Outillage :** Nmap 7.95, Wireshark / Tshark 4.4, Linux UFW / nftables',
    '',
    '## 1. Synthèse Exécutive & Bilan du Contre-Audit',
    '',
    `| Indicateur | État initial (2026-11-10) | Contre-audit (2026-11-16) | Évolution |`,
    `| --- | ---: | ---: | ---: |`,
    `| Ports ouverts exposés | ${diff.baselineOpenCount} | ${diff.retestOpenCount} | -${diff.reductionPercent}% |`,
    `| Constats enregistrés | ${findings.length} | ${openFindings.length} ouverts | ${remediatedFindings.length} corrigés |`,
    `| Constats Critiques / Élevés | ${findings.filter((f) => f.severity === 'Critical' || f.severity === 'High').length} | ${openFindings.filter((f) => f.severity === 'Critical' || f.severity === 'High').length} | Vérifié |`,
    '',
    '## 2. Périmètre Autorisé & Architecture VLAN',
    '',
    '| VLAN | Nom | CIDR | Zone de confiance | Rôle |',
    '| --- | --- | --- | --- | --- |',
    ...vlans.map((v) => `| ${v.vlanTag} | ${v.name} | \`${v.cidr}\` | ${formatTrustZoneFr(v.trustZone)} | ${v.purpose} |`),
    '',
    '## 3. Constats de Sécurité & Statut de Remédiation',
    '',
  ];

  for (const f of findings) {
    lines.push(
      `### ${f.id} : ${f.title} (${formatSeverityFr(f.severity)} · CVSS ${f.cvssScore.toFixed(1)} · ${formatStatusFr(f.status)})`,
      '',
      `- **Cible :** \`${f.hostIp}\` (${f.vlanName}) ${f.port ? `· Port \`${f.port}/${f.protocol}\`` : ''}`,
      `- **Vecteur CVSS :** \`${f.cvssVector}\``,
      `- **Impact :** ${f.businessImpact}`,
      `- **Référence preuve :** \`${f.evidenceRef}\``,
      `- **Remédiation :** ${f.remediationSummary}`,
      `- **Vérification contre-audit :** ${f.retestVerifiedDate ? `Vérifié le ${f.retestVerifiedDate}` : 'En attente'} — \`${f.retestCommand}\``,
      '',
    );
  }

  lines.push(
    '## 4. Manifeste des Preuves Datées (Intégrité SHA-256)',
    '',
    '| Dossier | Artefact | Type | Anonymisé | SHA-256 |',
    '| --- | --- | --- | --- | --- |',
    ...artifacts.map(
      (a) =>
        `| \`${a.folder}\` | \`${a.filename}\` | ${a.artifactType} | ${a.redacted ? 'Oui' : 'N/A'} | \`${a.sha256.slice(0, 16)}...\` |`,
    ),
    '',
  );

  return lines.join('\n');
}
