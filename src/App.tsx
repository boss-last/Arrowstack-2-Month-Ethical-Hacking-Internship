import { useMemo, useState } from 'react';
import { CheckCircle2, X } from 'lucide-react';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { OverviewScopeView } from './components/OverviewScopeView';
import { ReconEvidenceView } from './components/ReconEvidenceView';
import { FindingsCvssView } from './components/FindingsCvssView';
import { RemediationRetestView } from './components/RemediationRetestView';
import { DeliverablesView } from './components/DeliverablesView';
import {
  BASELINE_NMAP_OUTPUT,
  EVIDENCE_ARTIFACTS,
  INITIAL_FINDINGS,
  LAB_HOSTS,
  LIMITATIONS_AND_ROADMAP,
  PACKET_FRAMES,
  RETEST_NMAP_OUTPUT,
  SEGMENTATION_RULES,
  VIVA_QUESTIONS,
} from './data/labDataset';
import type {
  CvssMetrics,
  Finding,
  NavSection,
  ParsedHostResult,
  ParsedPort,
} from './types/assessment';
import {
  calculateCvssV31,
  DEFAULT_LAB_VLANS,
  diffScans,
  generateAssessmentMarkdown,
  parseNmapOutput,
} from './utils/networkParser';

function triggerDownload(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

export default function App() {
  const [activeSection, setActiveSection] = useState<NavSection>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [findings, setFindings] = useState<Finding[]>(INITIAL_FINDINGS);
  const [notice, setNotice] = useState<string | null>(null);

  const navigateSection = (section: NavSection) => {
    setActiveSection(section);
    window.scrollTo({ top: 0, behavior: 'instant' });
  };

  const scanDiff = useMemo(() => {
    const baseline = parseNmapOutput(BASELINE_NMAP_OUTPUT, DEFAULT_LAB_VLANS);
    const retest = parseNmapOutput(RETEST_NMAP_OUTPUT, DEFAULT_LAB_VLANS);
    return diffScans(baseline, retest);
  }, []);

  const openFindingCount = useMemo(
    () => findings.filter((f) => f.status === 'Open').length,
    [findings],
  );

  const existingFindingKeys = useMemo(() => {
    const keys = new Set<string>();
    for (const f of findings) {
      if (f.port) keys.add(`${f.hostIp}:${f.port}`);
    }
    return keys;
  }, [findings]);

  const showNotice = (msg: string) => {
    setNotice(msg);
  };

  const handlePromotePortToFinding = (host: ParsedHostResult, port: ParsedPort) => {
    const nextNum = findings.length + 1;
    const id = `NET-${String(nextNum).padStart(2, '0')}`;
    const metrics: CvssMetrics =
      port.riskLevel === 'Critical'
        ? { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' }
        : port.riskLevel === 'High'
          ? { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' }
          : { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' };

    const { score, severity, vector } = calculateCvssV31(metrics);
    const newFinding: Finding = {
      id,
      title: `Service ${port.service.toUpperCase()} exposé sur ${host.hostname} (${port.port}/${port.protocol})`,
      hostIp: host.ip,
      vlanName: host.vlanMatch ?? 'Lab autorisé',
      port: port.port,
      protocol: port.protocol,
      category: port.port === 21 || port.port === 23 || port.port === 80 ? 'Cleartext Traffic' : 'Exposed Service',
      severity,
      cvssScore: score,
      cvssVector: vector,
      cvssMetrics: metrics,
      status: 'Open',
      summary: port.riskNote,
      businessImpact: `Expose ${port.service} (${port.version || 'version non précisée'}) entre les segments du laboratoire autorisé.`,
      reproducibleSteps: [
        `Exécuter la sonde ciblée : nmap -sV -p ${port.port} ${host.ip}`,
        `Vérifier que ${port.port}/${port.protocol} répond ouvert et inspecter la bannière.`,
      ],
      evidenceRef: `2026-11-17_parser/nmap_${host.ip}.txt`,
      remediationSummary: `Désactiver ${port.service} ou restreindre TCP/${port.port} par ACL VLAN.`,
      configBefore: `# Service ${port.service} en écoute sur ${host.ip}:${port.port}`,
      configAfter: `ufw deny ${port.port}/${port.protocol}`,
      retestCommand: `nmap -sS -p ${port.port} ${host.ip}`,
      retestOutput: 'En attente de contre-audit.',
      retestVerifiedDate: null,
    };

    setFindings((prev) => [newFinding, ...prev]);
    showNotice(`Port ${host.ip}:${port.port} (${port.service}) promu en constat ${id}.`);
  };

  const handleAddFinding = (finding: Finding) => {
    setFindings((prev) => [finding, ...prev]);
    showNotice(`Constat ${finding.id} enregistré (${finding.title}).`);
  };

  const handleUpdateFindingCvss = (id: string, metrics: CvssMetrics) => {
    const { score, severity, vector } = calculateCvssV31(metrics);
    setFindings((prev) =>
      prev.map((f) =>
        f.id === id
          ? { ...f, cvssMetrics: metrics, cvssScore: score, severity, cvssVector: vector }
          : f,
      ),
    );
  };

  const handleToggleFindingRetest = (findingId: string) => {
    setFindings((prev) =>
      prev.map((f) => {
        if (f.id !== findingId) return f;
        const nextStatus = f.status === 'Remediated' ? 'Open' : 'Remediated';
        return {
          ...f,
          status: nextStatus,
          retestVerifiedDate: nextStatus === 'Remediated' ? '2026-11-17' : null,
          retestOutput:
            nextStatus === 'Remediated'
              ? 'Configuration durcie et état du port validés par contrôle après remédiation.'
              : 'Rouvert pour vérification complémentaire.',
        };
      }),
    );
  };

  const handleExportMarkdown = () => {
    const md = generateAssessmentMarkdown({
      vlans: DEFAULT_LAB_VLANS,
      findings,
      artifacts: EVIDENCE_ARTIFACTS,
      diff: scanDiff,
      generatedDate: '2026-11-17',
    });
    triggerDownload('rapport-audit-securite-reseau.md', md, 'text/markdown;charset=utf-8');
    showNotice('Rapport Markdown exporté (rapport-audit-securite-reseau.md).');
  };

  const handleExportJsonManifest = () => {
    const payload = {
      generatedDate: '2026-11-17',
      authorizedScope: '10.20.0.0/16',
      vlans: DEFAULT_LAB_VLANS,
      scanDiff,
      findings,
      artifacts: EVIDENCE_ARTIFACTS,
    };
    triggerDownload(
      'manifeste-preuves-securite-reseau.json',
      JSON.stringify(payload, null, 2),
      'application/json;charset=utf-8',
    );
    showNotice('Manifeste JSON exporté (manifeste-preuves-securite-reseau.json).');
  };

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <Sidebar
        activeSection={activeSection}
        onSelectSection={navigateSection}
        openFindingCount={openFindingCount}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          activeSection={activeSection}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          onExportReport={handleExportMarkdown}
        />

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
          {notice && (
            <div
              role="status"
              aria-live="polite"
              className="mb-6 flex items-center justify-between gap-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs font-medium text-emerald-950"
            >
              <span className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-700" aria-hidden="true" />
                <span>{notice}</span>
              </span>
              <button
                type="button"
                onClick={() => setNotice(null)}
                aria-label="Fermer la notification"
                className="rounded p-1 text-emerald-800 hover:bg-emerald-100"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          )}

          {activeSection === 'overview' && (
            <OverviewScopeView
              vlans={DEFAULT_LAB_VLANS}
              hosts={LAB_HOSTS}
              segmentationRules={SEGMENTATION_RULES}
              findings={findings}
              scanDiff={scanDiff}
              onNavigateToSection={(sec) => navigateSection(sec)}
            />
          )}

          {activeSection === 'recon' && (
            <ReconEvidenceView
              vlans={DEFAULT_LAB_VLANS}
              packetFrames={PACKET_FRAMES}
              artifacts={EVIDENCE_ARTIFACTS}
              existingFindingKeys={existingFindingKeys}
              onPromotePortToFinding={handlePromotePortToFinding}
            />
          )}

          {activeSection === 'findings' && (
            <FindingsCvssView
              findings={findings}
              vlans={DEFAULT_LAB_VLANS}
              onAddFinding={handleAddFinding}
              onUpdateFindingCvss={handleUpdateFindingCvss}
            />
          )}

          {activeSection === 'retest' && (
            <RemediationRetestView
              findings={findings}
              scanDiff={scanDiff}
              limitations={LIMITATIONS_AND_ROADMAP}
              onToggleFindingRetest={handleToggleFindingRetest}
            />
          )}

          {activeSection === 'deliverables' && (
            <DeliverablesView
              vlans={DEFAULT_LAB_VLANS}
              findings={findings}
              artifacts={EVIDENCE_ARTIFACTS}
              scanDiff={scanDiff}
              vivaQuestions={VIVA_QUESTIONS}
              onExportMarkdown={handleExportMarkdown}
              onExportJsonManifest={handleExportJsonManifest}
            />
          )}
        </main>
      </div>
    </div>
  );
}
