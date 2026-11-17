export type NavSection =
  | 'overview'
  | 'recon'
  | 'findings'
  | 'retest'
  | 'deliverables';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type FindingStatus = 'Open' | 'Remediated' | 'Accepted Risk';

export type StakeholderRole = 'technical' | 'executive';

export interface VlanSegment {
  id: string;
  vlanTag: number;
  name: string;
  cidr: string;
  purpose: string;
  gateway: string;
  trustZone: 'Untrusted' | 'Semi-Trusted' | 'Restricted' | 'Isolated Admin';
}

export interface LabHost {
  ip: string;
  hostname: string;
  vlanId: string;
  os: string;
  role: string;
  baselineOpenPorts: number[];
  retestOpenPorts: number[];
}

export interface SegmentationRule {
  sourceVlanId: string;
  destVlanId: string;
  baselineState: 'Unrestricted' | 'Permissive' | 'Blocked';
  baselineDetail: string;
  retestState: 'Blocked' | 'TLS/Restricted' | 'Denied';
  retestDetail: string;
}

export interface ParsedPort {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'filtered' | 'closed' | 'open|filtered';
  service: string;
  version: string;
  riskLevel: Severity | 'Nominal';
  riskNote: string;
}

export interface ParsedHostResult {
  ip: string;
  hostname: string;
  vlanMatch: string | null;
  inScope: boolean;
  hostState: 'up' | 'down' | 'filtered';
  ports: ParsedPort[];
}

export interface NmapParseResult {
  valid: boolean;
  error: string | null;
  warnings: string[];
  hosts: ParsedHostResult[];
  totalOpenPorts: number;
  flaggedRiskPorts: number;
  outOfScopeIps: string[];
}

export interface ScanDiffSummary {
  closedPorts: Array<{ ip: string; port: number; service: string }>;
  persistingOpenPorts: Array<{ ip: string; port: number; service: string }>;
  newlyOpenedPorts: Array<{ ip: string; port: number; service: string }>;
  baselineOpenCount: number;
  retestOpenCount: number;
  reductionPercent: number;
}

export interface PacketFrame {
  frameNumber: number;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  protocol: string;
  length: number;
  info: string;
  capturePhase: 'baseline' | 'retest';
  cleartextAlert: boolean;
  decodedSummary: string;
  redactionApplied: boolean;
}

export interface CvssMetrics {
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'R';
  S: 'U' | 'C';
  C: 'H' | 'L' | 'N';
  I: 'H' | 'L' | 'N';
  A: 'H' | 'L' | 'N';
}

export interface Finding {
  id: string;
  title: string;
  hostIp: string;
  vlanName: string;
  port: number | null;
  protocol: string;
  category: 'Exposed Service' | 'Weak Configuration' | 'Segmentation Gap' | 'Cleartext Traffic';
  severity: Severity;
  cvssScore: number;
  cvssVector: string;
  cvssMetrics: CvssMetrics;
  status: FindingStatus;
  summary: string;
  businessImpact: string;
  reproducibleSteps: string[];
  evidenceRef: string;
  remediationSummary: string;
  configBefore: string;
  configAfter: string;
  retestCommand: string;
  retestOutput: string;
  retestVerifiedDate: string | null;
}

export interface EvidenceArtifact {
  id: string;
  folder: '2026-11-10_baseline' | '2026-11-14_remediation' | '2026-11-16_retest';
  filename: string;
  artifactType: 'Nmap Scan' | 'Wireshark PCAP' | 'Firewall Ruleset' | 'Config Diff' | 'Retest Log';
  sha256: string;
  redacted: boolean;
  command: string;
  previewExcerpt: string;
}

export interface ScopeValidationResult {
  valid: boolean;
  inScope: boolean;
  normalizedIp: string;
  matchedVlan: VlanSegment | null;
  message: string;
}

export interface LimitationItem {
  id: string;
  area: string;
  limitation: string;
  mitigationOrNextStep: string;
  scaleHorizon: 'Immediate' | '30-Day' | '10x Production Scale';
}

export interface VivaQuestion {
  id: string;
  question: string;
  answer: string;
}
