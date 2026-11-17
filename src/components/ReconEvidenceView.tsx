import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  FileCode2,
  FolderOpen,
  Plus,
  Search,
  ShieldAlert,
} from 'lucide-react';
import type {
  EvidenceArtifact,
  NmapParseResult,
  PacketFrame,
  ParsedHostResult,
  ParsedPort,
  Severity,
  VlanSegment,
} from '../types/assessment';
import { BASELINE_NMAP_OUTPUT, RETEST_NMAP_OUTPUT } from '../data/labDataset';
import { formatSeverityFr, parseNmapOutput } from '../utils/networkParser';

interface ReconEvidenceViewProps {
  vlans: VlanSegment[];
  packetFrames: PacketFrame[];
  artifacts: EvidenceArtifact[];
  existingFindingKeys: Set<string>;
  onPromotePortToFinding: (host: ParsedHostResult, port: ParsedPort) => void;
}

const EDGE_CASE_SCAN_SAMPLE = `# Test des cas limites : cible publique hors périmètre, hôte injoignable et Telnet exposé
Nmap scan report for external-target.example (8.8.8.8)
Host is up (0.015s latency).
PORT   STATE SERVICE
53/tcp open  domain

Nmap scan report for dmz-legacy (10.20.10.25)
Host is up (0.0011s latency).
PORT     STATE SERVICE VERSION
23/tcp   open  telnet  Linux telnetd
21/tcp   open  ftp     vsftpd 3.0.3

Nmap scan report for dormant-host (10.20.30.99)
Note: Host seems down. If it is really up, try -Pn.`;

function severityTextClass(level: Severity | 'Nominal'): string {
  switch (level) {
    case 'Critical':
      return 'text-red-700 font-semibold';
    case 'High':
      return 'text-orange-700 font-semibold';
    case 'Medium':
      return 'text-amber-700 font-semibold';
    case 'Low':
      return 'text-blue-700 font-medium';
    default:
      return 'text-emerald-700 font-medium';
  }
}

export function ReconEvidenceView({
  vlans,
  packetFrames,
  artifacts,
  existingFindingKeys,
  onPromotePortToFinding,
}: ReconEvidenceViewProps) {
  const [rawScanText, setRawScanText] = useState(BASELINE_NMAP_OUTPUT);
  const [activePreset, setActivePreset] = useState<'baseline' | 'retest' | 'edge' | 'custom'>('baseline');
  const [parseResult, setParseResult] = useState<NmapParseResult>(() =>
    parseNmapOutput(BASELINE_NMAP_OUTPUT, vlans),
  );

  const [capturePhase, setCapturePhase] = useState<'baseline' | 'retest'>('baseline');
  const [cleartextOnly, setCleartextOnly] = useState(false);
  const [packetQuery, setPacketQuery] = useState('');
  const [selectedFrame, setSelectedFrame] = useState<PacketFrame | null>(packetFrames[0] ?? null);
  const [selectedFolder, setSelectedFolder] = useState<
    'all' | EvidenceArtifact['folder']
  >('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleAnalyze = () => {
    setParseResult(parseNmapOutput(rawScanText, vlans));
  };

  const loadPreset = (preset: 'baseline' | 'retest' | 'edge') => {
    setActivePreset(preset);
    const content =
      preset === 'baseline'
        ? BASELINE_NMAP_OUTPUT
        : preset === 'retest'
          ? RETEST_NMAP_OUTPUT
          : EDGE_CASE_SCAN_SAMPLE;
    setRawScanText(content);
    setParseResult(parseNmapOutput(content, vlans));
  };

  const handleCopyCommand = async (id: string, cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
    } catch {
      // Clipboard may be restricted in headless contexts
    }
  };

  const filteredFrames = packetFrames.filter((f) => {
    if (f.capturePhase !== capturePhase) return false;
    if (cleartextOnly && !f.cleartextAlert) return false;
    if (packetQuery.trim()) {
      const q = packetQuery.toLowerCase();
      return (
        f.protocol.toLowerCase().includes(q) ||
        f.sourceIp.includes(q) ||
        f.destIp.includes(q) ||
        f.info.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const filteredArtifacts =
    selectedFolder === 'all'
      ? artifacts
      : artifacts.filter((a) => a.folder === selectedFolder);

  return (
    <div className="space-y-8">
      {/* Analyseur Nmap automatisé & Garde-fou de périmètre */}
      <section aria-labelledby="nmap-analyzer-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 id="nmap-analyzer-heading" className="font-display text-lg font-semibold text-slate-900">
              Analyseur Nmap Automatisé &amp; Contrôle de Périmètre
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Collez une sortie Nmap standard ou grepable pour appliquer les règles de périmètre <span className="font-mono text-slate-900">10.20.0.0/16</span>, classifier les ports risqués et promouvoir les expositions en constats.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => loadPreset('baseline')}
              className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                activePreset === 'baseline'
                  ? 'border-blue-700 bg-blue-50 text-blue-800'
                  : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
              }`}
            >
              Scan initial
            </button>
            <button
              type="button"
              onClick={() => loadPreset('retest')}
              className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                activePreset === 'retest'
                  ? 'border-blue-700 bg-blue-50 text-blue-800'
                  : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
              }`}
            >
              Scan contre-audit
            </button>
            <button
              type="button"
              onClick={() => loadPreset('edge')}
              className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                activePreset === 'edge'
                  ? 'border-blue-700 bg-blue-50 text-blue-800'
                  : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
              }`}
            >
              Jeu de cas limites
            </button>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-6 xl:grid-cols-12 xl:items-start">
          <div className="xl:sticky xl:top-20 xl:col-span-5">
            <label htmlFor="nmap-raw-input" className="block text-xs font-medium text-slate-700">
              Sortie Nmap brute (<span className="font-mono">-oN</span> ou <span className="font-mono">-oG</span>)
            </label>
            <textarea
              id="nmap-raw-input"
              rows={20}
              value={rawScanText}
              onChange={(e) => {
                setRawScanText(e.target.value);
                setActivePreset('custom');
              }}
              className="mt-1.5 w-full rounded-md border border-slate-300 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-100 focus:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
              placeholder="Collez une sortie Nmap..."
            />
            <div className="mt-3 flex items-center justify-between gap-3">
              <span className="text-xs text-slate-500">
                Les IP hors périmètre sont bloquées avant l’analyse des ports.
              </span>
              <button
                type="button"
                onClick={handleAnalyze}
                className="rounded-md bg-blue-700 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700 whitespace-nowrap shrink-0"
              >
                Analyser la sortie
              </button>
            </div>
          </div>

          <div className="xl:col-span-7">
            {!parseResult.valid ? (
              <div
                role="alert"
                className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-900"
              >
                <div className="flex items-center gap-2 font-semibold">
                  <ShieldAlert className="h-4 w-4 text-red-700" aria-hidden="true" />
                  <span>Erreur d’analyse du scan</span>
                </div>
                <p className="mt-1.5">{parseResult.error}</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4 rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-xs">
                  <div className="flex flex-wrap items-center gap-4 tabular-nums">
                    <span className="font-medium text-slate-900">
                      {parseResult.hosts.length} hôtes autorisés
                    </span>
                    <span className="text-slate-300" aria-hidden="true">·</span>
                    <span className="font-medium text-slate-900">
                      {parseResult.totalOpenPorts} ports ouverts
                    </span>
                    <span className="text-slate-300" aria-hidden="true">·</span>
                    <span
                      className={`font-semibold ${
                        parseResult.flaggedRiskPorts > 0 ? 'text-red-700' : 'text-emerald-700'
                      }`}
                    >
                      {parseResult.flaggedRiskPorts} services risqués signalés
                    </span>
                  </div>
                </div>

                {parseResult.warnings.length > 0 && (
                  <div
                    role="status"
                    className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950"
                  >
                    <div className="flex items-center gap-1.5 font-semibold">
                      <AlertTriangle className="h-3.5 w-3.5 text-amber-700" aria-hidden="true" />
                      <span>Alertes de périmètre &amp; cas limites</span>
                    </div>
                    <ul className="mt-1 list-disc space-y-0.5 pl-5">
                      {parseResult.warnings.map((w, idx) => (
                        <li key={idx}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="overflow-x-auto rounded-md border border-slate-200">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 font-medium text-slate-600">
                        <th className="px-3 py-2.5">Hôte / VLAN</th>
                        <th className="px-3 py-2.5">Port</th>
                        <th className="px-3 py-2.5">État</th>
                        <th className="px-3 py-2.5">Service / Version</th>
                        <th className="px-3 py-2.5">Évaluation</th>
                        <th className="px-3 py-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 bg-white">
                      {parseResult.hosts.flatMap((host) => {
                        if (host.ports.length === 0) {
                          return [
                            <tr key={`${host.ip}-down`} className="bg-slate-50/40">
                              <td className="px-3 py-2.5 font-mono text-slate-900">
                                {host.ip} ({host.hostname})
                              </td>
                              <td className="px-3 py-2.5 font-mono text-slate-500">—</td>
                              <td className="px-3 py-2.5 text-slate-600">{host.hostState}</td>
                              <td className="px-3 py-2.5 text-slate-500" colSpan={3}>
                                Aucun port ouvert signalé ({host.vlanMatch})
                              </td>
                            </tr>,
                          ];
                        }
                        return host.ports.map((port) => {
                          const key = `${host.ip}:${port.port}`;
                          const alreadyLogged = existingFindingKeys.has(key);
                          const canPromote =
                            (port.state === 'open' || port.state === 'open|filtered') &&
                            port.riskLevel !== 'Nominal' &&
                            !alreadyLogged;

                          return (
                            <tr key={`${host.ip}-${port.port}-${port.protocol}`} className="hover:bg-slate-50">
                              <td className="px-3 py-2.5">
                                <div className="font-mono font-medium text-slate-900">{host.ip}</div>
                                <div className="text-slate-500">{host.vlanMatch}</div>
                              </td>
                              <td className="px-3 py-2.5 font-mono tabular-nums text-slate-900 whitespace-nowrap">
                                {port.port}/{port.protocol}
                              </td>
                              <td className="px-3 py-2.5 font-mono whitespace-nowrap">
                                <span
                                  className={
                                    port.state === 'open'
                                      ? 'font-semibold text-slate-900'
                                      : 'text-emerald-700'
                                  }
                                >
                                  {port.state}
                                </span>
                              </td>
                              <td className="px-3 py-2.5">
                                <div className="font-mono text-slate-900">{port.service}</div>
                                {port.version && (
                                  <div className="text-slate-500">{port.version}</div>
                                )}
                              </td>
                              <td className="px-3 py-2.5">
                                <div className={severityTextClass(port.riskLevel)}>
                                  {formatSeverityFr(port.riskLevel)}
                                </div>
                                <div className="mt-0.5 max-w-xs text-slate-600">{port.riskNote}</div>
                              </td>
                              <td className="px-3 py-2.5 text-right whitespace-nowrap">
                                {alreadyLogged ? (
                                  <span className="text-slate-500">Enregistré</span>
                                ) : canPromote ? (
                                  <button
                                    type="button"
                                    onClick={() => onPromotePortToFinding(host, port)}
                                    className="inline-flex items-center gap-1 rounded border border-blue-200 bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-800 hover:bg-blue-100 focus-visible:outline-2 focus-visible:outline-blue-700"
                                  >
                                    <Plus className="h-3 w-3" aria-hidden="true" />
                                    <span>Promouvoir</span>
                                  </button>
                                ) : (
                                  <span className="text-slate-400">—</span>
                                )}
                              </td>
                            </tr>
                          );
                        });
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Inspecteur de captures Wireshark */}
      <section aria-labelledby="wireshark-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 id="wireshark-heading" className="font-display text-lg font-semibold text-slate-900">
              Preuves par Capture Réseau Wireshark
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Inspectez les trames <span className="font-mono">.pcapng</span> décodées des fuites en clair initiales et du trafic chiffré/filtré au contre-audit. Les secrets sont anonymisés avant archivage.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div role="group" aria-label="Phase de capture" className="inline-flex rounded-lg bg-slate-100 p-1">
              <button
                type="button"
                onClick={() => {
                  setCapturePhase('baseline');
                  const first = packetFrames.find((p) => p.capturePhase === 'baseline') ?? null;
                  setSelectedFrame(first);
                }}
                className={`rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap shrink-0 ${
                  capturePhase === 'baseline'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Capture initiale
              </button>
              <button
                type="button"
                onClick={() => {
                  setCapturePhase('retest');
                  const first = packetFrames.find((p) => p.capturePhase === 'retest') ?? null;
                  setSelectedFrame(first);
                }}
                className={`rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap shrink-0 ${
                  capturePhase === 'retest'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Capture contre-audit
              </button>
            </div>

            <label className="inline-flex cursor-pointer items-center gap-2 text-xs font-medium text-slate-700">
              <input
                type="checkbox"
                checked={cleartextOnly}
                onChange={(e) => setCleartextOnly(e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
              />
              <span>Alertes en clair uniquement</span>
            </label>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-2">
          <div className="relative max-w-sm flex-1">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-slate-400" aria-hidden="true" />
            <input
              type="text"
              aria-label="Filtrer les trames"
              value={packetQuery}
              onChange={(e) => setPacketQuery(e.target.value)}
              placeholder="Filtrer par IP ou protocole (TELNET, TLSv1.3)..."
              className="w-full rounded-md border border-slate-300 bg-white py-2 pr-3 pl-9 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
            />
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="overflow-x-auto rounded-md border border-slate-200 lg:col-span-7">
            <table className="w-full border-collapse text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 font-sans font-medium text-slate-600">
                  <th className="px-3 py-2">N°</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Destination</th>
                  <th className="px-3 py-2">Proto</th>
                  <th className="px-3 py-2">Info</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 bg-white">
                {filteredFrames.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center font-sans text-slate-500">
                      Aucune trame ne correspond au filtre dans la phase {capturePhase === 'baseline' ? 'initiale' : 'contre-audit'}.
                    </td>
                  </tr>
                ) : (
                  filteredFrames.map((frame) => {
                    const isSelected = selectedFrame?.frameNumber === frame.frameNumber && selectedFrame?.capturePhase === frame.capturePhase;
                    return (
                      <tr
                        key={`${frame.capturePhase}-${frame.frameNumber}`}
                        onClick={() => setSelectedFrame(frame)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-blue-50'
                            : frame.cleartextAlert
                              ? 'bg-red-50/40 hover:bg-red-50/70'
                              : 'hover:bg-slate-50'
                        }`}
                      >
                        <td className="px-3 py-2 tabular-nums text-slate-700">{frame.frameNumber}</td>
                        <td className="px-3 py-2 tabular-nums text-slate-900">{frame.sourceIp}</td>
                        <td className="px-3 py-2 tabular-nums text-slate-900">{frame.destIp}</td>
                        <td className="px-3 py-2 font-semibold text-slate-800">{frame.protocol}</td>
                        <td className="px-3 py-2 text-slate-700">
                          <button
                            type="button"
                            onClick={() => setSelectedFrame(frame)}
                            className="text-left hover:underline focus-visible:outline-2 focus-visible:outline-blue-700"
                          >
                            {frame.info}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="rounded-md border border-slate-200 bg-slate-50 p-4 lg:col-span-5">
            {selectedFrame ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2 border-b border-slate-200 pb-2">
                  <span className="font-mono text-xs font-semibold text-slate-900">
                    Trame #{selectedFrame.frameNumber} · {selectedFrame.protocol}
                  </span>
                  <span
                    className={`text-xs font-semibold ${
                      selectedFrame.cleartextAlert ? 'text-red-700' : 'text-emerald-700'
                    }`}
                  >
                    {selectedFrame.cleartextAlert ? 'Risque en clair' : 'Chiffré / Bloqué'}
                  </span>
                </div>
                <p className="font-mono text-xs tabular-nums text-slate-600">
                  {selectedFrame.timestamp} · {selectedFrame.sourceIp} → {selectedFrame.destIp} · {selectedFrame.length} octets
                </p>
                <p className="text-sm leading-relaxed text-slate-700">
                  {selectedFrame.decodedSummary}
                </p>
                {selectedFrame.redactionApplied && (
                  <p className="text-xs font-medium text-slate-600">
                    Confidentialité &amp; Intégrité : Identifiants en clair masqués par <span className="font-mono">[REDACTED]</span>.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-sm text-slate-500">Sélectionnez une trame pour afficher son résumé décodé.</p>
            )}
          </div>
        </div>
      </section>

      {/* Coffre de preuves datées */}
      <section aria-labelledby="evidence-locker-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="evidence-locker-heading" className="font-display text-lg font-semibold text-slate-900">
              Dossier de Preuves Datées &amp; Empreintes SHA-256
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Commandes CLI reproductibles et empreintes SHA-256 classées par phase d’évaluation.
            </p>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {(['all', '2026-11-10_baseline', '2026-11-14_remediation', '2026-11-16_retest'] as const).map(
              (folder) => (
                <button
                  key={folder}
                  type="button"
                  onClick={() => setSelectedFolder(folder)}
                  className={`rounded-md px-3 py-1.5 font-mono text-xs transition-colors whitespace-nowrap shrink-0 ${
                    selectedFolder === folder
                      ? 'bg-slate-900 text-white'
                      : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  {folder === 'all' ? 'Tous les dossiers' : folder}
                </button>
              ),
            )}
          </div>
        </div>

        <div className="mt-4 divide-y divide-slate-200 rounded-md border border-slate-200">
          {filteredArtifacts.map((item) => (
            <div key={item.id} className="p-4">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <FolderOpen className="h-4 w-4 text-slate-500" aria-hidden="true" />
                  <span className="font-mono font-semibold text-slate-900">
                    {item.folder}/{item.filename}
                  </span>
                  <span className="text-slate-300" aria-hidden="true">·</span>
                  <span className="text-xs text-slate-600">{item.artifactType}</span>
                  {item.redacted && (
                    <>
                      <span className="text-slate-300" aria-hidden="true">·</span>
                      <span className="text-xs font-medium text-emerald-700">
                        Secrets anonymisés
                      </span>
                    </>
                  )}
                </div>
                <span className="font-mono text-xs text-slate-500">
                  SHA-256 : {item.sha256.slice(0, 16)}…
                </span>
              </div>

              <p className="mt-2 text-xs leading-relaxed text-slate-600">{item.previewExcerpt}</p>

              <div className="mt-3 flex items-center justify-between gap-3 rounded bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200">
                <span className="flex items-center gap-2 overflow-x-auto whitespace-nowrap">
                  <FileCode2 className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
                  <code>{item.command}</code>
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyCommand(item.id, item.command)}
                  aria-label={`Copier la commande pour ${item.filename}`}
                  className="inline-flex shrink-0 items-center gap-1 rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700 focus-visible:outline-2 focus-visible:outline-blue-500"
                >
                  {copiedId === item.id ? (
                    <>
                      <CheckCircle2 className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                      <span>Copié</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" aria-hidden="true" />
                      <span>Copier</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
