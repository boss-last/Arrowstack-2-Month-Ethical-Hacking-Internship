import { useState } from 'react';
import { CheckCircle2, Clock, Copy } from 'lucide-react';
import type { Finding, LimitationItem, ScanDiffSummary } from '../types/assessment';
import { formatSeverityFr, formatStatusFr } from '../utils/networkParser';

interface RemediationRetestViewProps {
  findings: Finding[];
  scanDiff: ScanDiffSummary;
  limitations: LimitationItem[];
  onToggleFindingRetest: (findingId: string) => void;
}

function formatHorizonFr(horizon: LimitationItem['scaleHorizon']): string {
  switch (horizon) {
    case 'Immediate':
      return 'Immédiat';
    case '30-Day':
      return 'Sous 30 jours';
    case '10x Production Scale':
      return 'Échelle 10× Prod';
  }
}

export function RemediationRetestView({
  findings,
  scanDiff,
  limitations,
  onToggleFindingRetest,
}: RemediationRetestViewProps) {
  const [selectedId, setSelectedId] = useState<string>(findings[0]?.id ?? '');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const selectedFinding = findings.find((f) => f.id === selectedId) ?? findings[0] ?? null;

  const handleCopyConfig = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
    } catch {
      // Clipboard unavailable in sandbox
    }
  };

  return (
    <div className="space-y-8">
      {/* Diffentiel Nmap avant / après */}
      <section aria-labelledby="scan-diff-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-3 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="scan-diff-heading" className="font-display text-lg font-semibold text-slate-900">
              Différentiel des Ports Nmap Avant / Après
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Comparaison déterministe entre l’état initial (<span className="font-mono">2026-11-10</span>) et le contre-audit (<span className="font-mono">2026-11-16</span>) depuis la sonde DMZ.
            </p>
          </div>
          <div className="font-mono text-sm font-semibold tabular-nums text-emerald-700">
            -{scanDiff.reductionPercent} % de surface exposée ({scanDiff.baselineOpenCount} → {scanDiff.retestOpenCount} ouverts)
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-md border border-slate-200 bg-slate-50/70 p-4">
            <h3 className="text-xs font-semibold text-slate-900">
              Fermés / Filtrés au contre-audit ({scanDiff.closedPorts.length})
            </h3>
            <ul className="mt-2.5 space-y-1.5 font-mono text-xs tabular-nums text-emerald-800">
              {scanDiff.closedPorts.map((item) => (
                <li key={`${item.ip}:${item.port}`}>
                  {item.ip}:{item.port} ({item.service})
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-md border border-slate-200 bg-slate-50/70 p-4">
            <h3 className="text-xs font-semibold text-slate-900">
              Services autorisés conservés ({scanDiff.persistingOpenPorts.length})
            </h3>
            <ul className="mt-2.5 space-y-1.5 font-mono text-xs tabular-nums text-slate-700">
              {scanDiff.persistingOpenPorts.map((item) => (
                <li key={`${item.ip}:${item.port}`}>
                  {item.ip}:{item.port} ({item.service})
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-md border border-slate-200 bg-slate-50/70 p-4">
            <h3 className="text-xs font-semibold text-slate-900">
              Port TLS durci remplaçant HTTP ({scanDiff.newlyOpenedPorts.length})
            </h3>
            <ul className="mt-2.5 space-y-1.5 font-mono text-xs tabular-nums text-blue-800">
              {scanDiff.newlyOpenedPorts.length === 0 ? (
                <li className="text-slate-500">Aucun nouveau port ouvert</li>
              ) : (
                scanDiff.newlyOpenedPorts.map((item) => (
                  <li key={`${item.ip}:${item.port}`}>
                    {item.ip}:{item.port} ({item.service})
                  </li>
                ))
              )}
            </ul>
          </div>
        </div>
      </section>

      {/* Correctifs & Vérification contre-audit */}
      <section aria-labelledby="remediation-diff-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 id="remediation-diff-heading" className="font-display text-lg font-semibold text-slate-900">
          Correctifs Défensifs &amp; Vérification du Contre-Audit
        </h2>
        <p className="mt-1 text-sm text-slate-600">
          Sélectionnez un constat pour consulter le différentiel de configuration Avant/Après et valider l’état du contre-audit.
        </p>

        <div className="mt-5 grid grid-cols-1 gap-6 xl:grid-cols-12">
          <div className="space-y-2 xl:col-span-5">
            {findings.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setSelectedId(f.id)}
                  className={`flex w-full items-start justify-between gap-3 rounded-md border p-3.5 text-left transition-colors focus-visible:outline-2 focus-visible:outline-blue-700 ${
                    isSelected
                      ? 'border-blue-600 bg-blue-50/60'
                      : 'border-slate-200 bg-white hover:bg-slate-50'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 font-mono text-xs text-slate-500">
                      <span className="font-semibold text-slate-900">{f.id}</span>
                      <span aria-hidden="true">·</span>
                      <span>{f.hostIp}</span>
                    </div>
                    <p className="mt-1 truncate text-sm font-medium text-slate-900">{f.title}</p>
                  </div>
                  <span
                    className={`inline-flex shrink-0 items-center gap-1 text-xs font-semibold ${
                      f.status === 'Remediated' ? 'text-emerald-700' : 'text-amber-700'
                    }`}
                  >
                    {f.status === 'Remediated' ? (
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                    ) : (
                      <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                    )}
                    <span>{formatStatusFr(f.status)}</span>
                  </span>
                </button>
              );
            })}
          </div>

          <div className="xl:col-span-7">
            {selectedFinding && (
              <div className="space-y-5 rounded-md border border-slate-200 bg-slate-50/60 p-5">
                <div className="flex flex-col gap-3 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <span className="font-mono text-xs font-semibold text-slate-500">
                      {selectedFinding.id} · {formatSeverityFr(selectedFinding.severity)}
                    </span>
                    <h3 className="mt-1 font-display text-base font-semibold text-slate-900">
                      {selectedFinding.title}
                    </h3>
                  </div>

                  <button
                    type="button"
                    onClick={() => onToggleFindingRetest(selectedFinding.id)}
                    className={`rounded-md px-3.5 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-blue-700 ${
                      selectedFinding.status === 'Remediated'
                        ? 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-100'
                        : 'bg-emerald-700 text-white hover:bg-emerald-800'
                    }`}
                  >
                    {selectedFinding.status === 'Remediated'
                      ? 'Rouvrir le constat'
                      : 'Valider et marquer corrigé'}
                  </button>
                </div>

                <p className="text-sm leading-relaxed text-slate-700">
                  {selectedFinding.remediationSummary}
                </p>

                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <div>
                    <span className="text-xs font-semibold text-red-700">
                      Avant (Configuration vulnérable)
                    </span>
                    <pre className="mt-1.5 overflow-x-auto rounded-md border border-red-200 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-red-200">
                      <code>{selectedFinding.configBefore}</code>
                    </pre>
                  </div>

                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-emerald-700">
                        Après (Configuration durcie)
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyConfig(selectedFinding.id, selectedFinding.configAfter)}
                        className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:underline"
                      >
                        <Copy className="h-3 w-3" aria-hidden="true" />
                        <span>{copiedId === selectedFinding.id ? 'Copié' : 'Copier'}</span>
                      </button>
                    </div>
                    <pre className="mt-1.5 overflow-x-auto rounded-md border border-emerald-200 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-emerald-200">
                      <code>{selectedFinding.configAfter}</code>
                    </pre>
                  </div>
                </div>

                <div className="rounded-md border border-slate-200 bg-white p-3.5 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900">Commande de contre-audit</span>
                    <span className="font-mono text-slate-500">
                      {selectedFinding.retestVerifiedDate
                        ? `Vérifié le ${selectedFinding.retestVerifiedDate}`
                        : 'Vérification en attente'}
                    </span>
                  </div>
                  <p className="mt-1.5 font-mono text-slate-800">$ {selectedFinding.retestCommand}</p>
                  <p className="mt-1 font-mono text-slate-600">{selectedFinding.retestOutput}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Limitations & Feuille de route 10x */}
      <section aria-labelledby="limitations-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 id="limitations-heading" className="font-display text-lg font-semibold text-slate-900">
          Limitations Documentées &amp; Feuille de Route Production
        </h2>
        <p className="mt-1 text-sm text-slate-600">
          Limites explicites du laboratoire isolé et évolutions réalistes requises pour un passage à l’échelle 10×.
        </p>

        <div className="mt-4 overflow-x-auto rounded-md border border-slate-200">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 font-medium text-slate-600">
                <th className="px-4 py-2.5">Domaine</th>
                <th className="px-4 py-2.5">Limite / Cas particulier</th>
                <th className="px-4 py-2.5">Amélioration recommandée</th>
                <th className="px-4 py-2.5 whitespace-nowrap">Horizon</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 bg-white">
              {limitations.map((item) => (
                <tr key={item.id} className="hover:bg-slate-50">
                  <td className="px-4 py-3 font-medium text-slate-900">{item.area}</td>
                  <td className="px-4 py-3 leading-relaxed text-slate-600">{item.limitation}</td>
                  <td className="px-4 py-3 leading-relaxed text-slate-700">
                    {item.mitigationOrNextStep}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-700 whitespace-nowrap">
                    {formatHorizonFr(item.scaleHorizon)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
