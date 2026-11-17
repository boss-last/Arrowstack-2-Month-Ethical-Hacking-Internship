import { useState, type FormEvent } from 'react';
import { CheckCircle2, AlertTriangle, ShieldAlert, ArrowRight } from 'lucide-react';
import type {
  Finding,
  LabHost,
  ScanDiffSummary,
  ScopeValidationResult,
  SegmentationRule,
  VlanSegment,
} from '../types/assessment';
import { formatTrustZoneFr, validateTargetInScope } from '../utils/networkParser';

interface OverviewScopeViewProps {
  vlans: VlanSegment[];
  hosts: LabHost[];
  segmentationRules: SegmentationRule[];
  findings: Finding[];
  scanDiff: ScanDiffSummary;
  onNavigateToSection: (section: 'recon' | 'findings' | 'retest') => void;
}

function formatRuleStateFr(state: string): string {
  switch (state) {
    case 'Unrestricted':
      return 'Sans restriction';
    case 'Permissive':
      return 'Permissive';
    case 'Blocked':
      return 'Bloquée';
    case 'TLS/Restricted':
      return 'TLS / Restreinte';
    case 'Denied':
      return 'Refusée';
    default:
      return state;
  }
}

export function OverviewScopeView({
  vlans,
  hosts,
  segmentationRules,
  findings,
  scanDiff,
  onNavigateToSection,
}: OverviewScopeViewProps) {
  const [topologyPhase, setTopologyPhase] = useState<'baseline' | 'retest'>('retest');
  const [targetIpInput, setTargetIpInput] = useState('10.20.20.14');
  const [scopeResult, setScopeResult] = useState<ScopeValidationResult>(() =>
    validateTargetInScope('10.20.20.14', vlans),
  );

  const openFindingsCount = findings.filter((f) => f.status === 'Open').length;
  const criticalHighBaseline = findings.filter(
    (f) => f.severity === 'Critical' || f.severity === 'High',
  ).length;
  const criticalHighOpen = findings.filter(
    (f) =>
      f.status === 'Open' && (f.severity === 'Critical' || f.severity === 'High'),
  ).length;
  const lateralPathsBaseline = segmentationRules.filter(
    (r) => r.baselineState !== 'Blocked',
  ).length;
  const lateralPathsRetest = segmentationRules.filter(
    (r) => r.retestState !== 'Blocked' && r.destVlanId === 'vlan-30' && r.sourceVlanId === 'vlan-10',
  ).length;

  const handleValidateScope = (e: FormEvent) => {
    e.preventDefault();
    setScopeResult(validateTargetInScope(targetIpInput, vlans));
  };

  return (
    <div className="space-y-8">
      {/* Cadrage & Partie Prenante */}
      <section aria-labelledby="problem-framing-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
          <div className="max-w-3xl space-y-2">
            <p className="text-xs font-medium text-blue-700">
              Audit de laboratoire autorisé · Périmètre 10.20.0.0/16 · 2026-11-10 au 2026-11-16
            </p>
            <h2
              id="problem-framing-heading"
              className="font-display text-2xl font-semibold tracking-tight text-slate-900 text-balance"
            >
              Exposition Réseau, Segmentation VLAN &amp; Contre-Audit Défensif
            </h2>
            <p className="text-sm leading-relaxed text-slate-600">
              Évaluation d’un environnement cloisonné à quatre VLAN afin d’identifier les services exposés, les flux en clair, les configurations faibles et les chemins latéraux avant mise en production. Conçu pour permettre une validation reproductible par un responsable Infrastructure ou SecOps.
            </p>
          </div>

          <div className="grid shrink-0 grid-cols-1 gap-3 border-t border-slate-200 pt-4 text-xs sm:grid-cols-3 lg:w-96 lg:grid-cols-1 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-6">
            <div>
              <span className="font-medium text-slate-900">Partie prenante principale</span>
              <p className="mt-0.5 text-slate-600">Responsable Infrastructure &amp; SecOps</p>
            </div>
            <div>
              <span className="font-medium text-slate-900">Décision éclairée</span>
              <p className="mt-0.5 text-slate-600">Valider la bascule VLAN &amp; les règles ACL</p>
            </div>
            <div>
              <span className="font-medium text-slate-900">Critère de succès</span>
              <p className="mt-0.5 text-slate-600">0 risque Critique/Élevé · 0 chemin DMZ vers Données</p>
            </div>
          </div>
        </div>
      </section>

      {/* Indicateurs Avant / Après */}
      <section aria-label="Indicateurs avant et après remédiation" className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Ports TCP exposés</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-slate-900">
              {scanDiff.retestOpenCount}
            </span>
            <span className="font-mono text-xs tabular-nums text-slate-500">
              contre {scanDiff.baselineOpenCount} (-{scanDiff.reductionPercent}%)
            </span>
          </div>
          <p className="mt-2 text-xs font-medium text-emerald-700">
            Contre-audit vérifié · Seuls TLS &amp; Bastion SSH actifs
          </p>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Constats Critiques &amp; Élevés</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-slate-900">
              {criticalHighOpen}
            </span>
            <span className="font-mono text-xs tabular-nums text-slate-500">
              contre {criticalHighBaseline} à l’état initial
            </span>
          </div>
          <p className="mt-2 text-xs font-medium text-emerald-700">
            Tous corrigés · {openFindingsCount} constat Faible/Moyen ouvert
          </p>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Chemins DMZ vers Données</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-slate-900">
              {lateralPathsRetest}
            </span>
            <span className="font-mono text-xs tabular-nums text-slate-500">
              contre {lateralPathsBaseline} liens permissifs
            </span>
          </div>
          <p className="mt-2 text-xs font-medium text-emerald-700">
            Appliqué · Politique nftables de refus par défaut
          </p>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Protocoles en clair observés</p>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-slate-900">
              0
            </span>
            <span className="font-mono text-xs tabular-nums text-slate-500">
              contre 4 (Telnet, HTTP, RESP, SMBv1)
            </span>
          </div>
          <p className="mt-2 text-xs font-medium text-emerald-700">
            Capture Wireshark conforme TLS 1.3 &amp; signature SMBv3
          </p>
        </div>
      </section>

      {/* Topologie & Matrice de segmentation */}
      <section aria-labelledby="topology-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 id="topology-heading" className="font-display text-lg font-semibold text-slate-900">
              Cartographie VLAN &amp; Exposition des Hôtes
            </h3>
            <p className="mt-1 text-sm text-slate-600">
              Basculez entre la découverte initiale et l’état après durcissement pour inspecter la joignabilité inter-VLAN et les ports ouverts.
            </p>
          </div>

          <div
            role="group"
            aria-label="Sélecteur de phase topologique"
            className="inline-flex rounded-lg bg-slate-100 p-1 self-start sm:self-auto"
          >
            <button
              type="button"
              onClick={() => setTopologyPhase('baseline')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-blue-700 ${
                topologyPhase === 'baseline'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              État initial (2026-11-10)
            </button>
            <button
              type="button"
              onClick={() => setTopologyPhase('retest')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-blue-700 ${
                topologyPhase === 'retest'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Après remédiation (2026-11-16)
            </button>
          </div>
        </div>

        {/* Grille 4 VLAN */}
        <div className="mt-6 grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
          {vlans.map((vlan) => {
            const vlanHosts = hosts.filter((h) => h.vlanId === vlan.id);
            return (
              <div key={vlan.id} className="flex flex-col">
                <div className="border-b border-slate-200 pb-3">
                  <h4 className="font-display text-sm font-semibold text-slate-900">
                    {vlan.name}
                  </h4>
                  <p className="mt-0.5 font-mono text-xs text-slate-500 tabular-nums">
                    {vlan.cidr} · {formatTrustZoneFr(vlan.trustZone)}
                  </p>
                  <p className="mt-1.5 text-xs text-slate-600">{vlan.purpose}</p>
                </div>

                <div className="mt-3 space-y-2.5">
                  {vlanHosts.map((host) => {
                    const ports =
                      topologyPhase === 'baseline'
                        ? host.baselineOpenPorts
                        : host.retestOpenPorts;
                    return (
                      <div
                        key={host.ip}
                        className="rounded-md border border-slate-200 bg-slate-50/60 p-3"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs font-semibold text-slate-900">
                            {host.hostname}
                          </span>
                          <span className="font-mono text-xs tabular-nums text-slate-500">
                            {host.ip}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-slate-600">{host.role}</p>
                        <p className="mt-2 font-mono text-xs tabular-nums text-slate-700">
                          Ports ouverts :{' '}
                          {ports.length > 0 ? (
                            <span
                              className={
                                topologyPhase === 'baseline' &&
                                ports.some((p) => [23, 6379, 445, 3306, 80].includes(p))
                                  ? 'font-semibold text-red-700'
                                  : 'font-semibold text-emerald-700'
                              }
                            >
                              {ports.join(', ')}
                            </span>
                          ) : (
                            <span className="font-medium text-emerald-700">
                              Aucun exposé vers DMZ
                            </span>
                          )}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {/* Matrice inter-VLAN */}
        <div className="mt-6">
          <h4 className="text-sm font-semibold text-slate-900">
            Matrice de filtrage inter-VLAN ({topologyPhase === 'baseline' ? 'Failles initiales' : 'État durci'})
          </h4>
          <div className="mt-3 overflow-x-auto rounded-md border border-slate-200">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-600">
                  <th className="px-4 py-2.5">Zone source</th>
                  <th className="px-4 py-2.5">Zone destination</th>
                  <th className="px-4 py-2.5">Politique</th>
                  <th className="px-4 py-2.5">Comportement observé</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 bg-white">
                {segmentationRules.map((rule) => {
                  const src = vlans.find((v) => v.id === rule.sourceVlanId)?.name ?? rule.sourceVlanId;
                  const dst = vlans.find((v) => v.id === rule.destVlanId)?.name ?? rule.destVlanId;
                  const state =
                    topologyPhase === 'baseline' ? rule.baselineState : rule.retestState;
                  const detail =
                    topologyPhase === 'baseline' ? rule.baselineDetail : rule.retestDetail;
                  const isRisk =
                    topologyPhase === 'baseline' &&
                    (state === 'Unrestricted' || state === 'Permissive');

                  return (
                    <tr key={`${rule.sourceVlanId}-${rule.destVlanId}`} className="hover:bg-slate-50">
                      <td className="px-4 py-2.5 font-medium text-slate-900 whitespace-nowrap">{src}</td>
                      <td className="px-4 py-2.5 font-medium text-slate-900 whitespace-nowrap">{dst}</td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 text-xs font-semibold ${
                            isRisk ? 'text-red-700' : 'text-emerald-700'
                          }`}
                        >
                          {isRisk ? (
                            <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                          ) : (
                            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          )}
                          <span>{formatRuleStateFr(state)}</span>
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-slate-600">{detail}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Validateur de périmètre autorisé */}
      <section aria-labelledby="scope-validator-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="lg:col-span-7">
            <h3 id="scope-validator-heading" className="font-display text-lg font-semibold text-slate-900">
              Garde-fou du Périmètre Autorisé
            </h3>
            <p className="mt-1 text-sm text-slate-600">
              Vérifiez toute cible IPv4 avant de lancer Nmap ou Wireshark. Les adresses externes ou hors du bloc <span className="font-mono text-slate-900">10.20.0.0/16</span> sont bloquées.
            </p>

            <form onSubmit={handleValidateScope} className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="flex-1">
                <label htmlFor="scope-ip-input" className="block text-xs font-medium text-slate-700">
                  Adresse IPv4 cible
                </label>
                <input
                  id="scope-ip-input"
                  type="text"
                  value={targetIpInput}
                  onChange={(e) => setTargetIpInput(e.target.value)}
                  placeholder="ex. 10.20.20.14 ou 8.8.8.8"
                  className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
                />
              </div>
              <button
                type="submit"
                className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 whitespace-nowrap shrink-0"
              >
                Vérifier la cible
              </button>
            </form>

            <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-500">
              <span>Jeux de test rapides :</span>
              <button
                type="button"
                onClick={() => {
                  setTargetIpInput('10.20.30.11');
                  setScopeResult(validateTargetInScope('10.20.30.11', vlans));
                }}
                className="font-mono text-blue-700 underline-offset-2 hover:underline"
              >
                10.20.30.11 (BDD autorisée)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTargetIpInput('8.8.8.8');
                  setScopeResult(validateTargetInScope('8.8.8.8', vlans));
                }}
                className="font-mono text-red-700 underline-offset-2 hover:underline"
              >
                8.8.8.8 (Externe bloquée)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTargetIpInput('10.20.999.4');
                  setScopeResult(validateTargetInScope('10.20.999.4', vlans));
                }}
                className="font-mono text-amber-700 underline-offset-2 hover:underline"
              >
                10.20.999.4 (Malformée)
              </button>
            </div>
          </div>

          <div className="lg:col-span-5">
            <div
              role="status"
              aria-live="polite"
              className={`h-full rounded-md border p-4 ${
                !scopeResult.valid
                  ? 'border-amber-200 bg-amber-50 text-amber-950'
                  : scopeResult.inScope
                    ? 'border-emerald-200 bg-emerald-50 text-emerald-950'
                    : 'border-red-200 bg-red-50 text-red-950'
              }`}
            >
              <div className="flex items-center gap-2 text-xs font-semibold">
                {!scopeResult.valid ? (
                  <AlertTriangle className="h-4 w-4 text-amber-700" aria-hidden="true" />
                ) : scopeResult.inScope ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-700" aria-hidden="true" />
                ) : (
                  <ShieldAlert className="h-4 w-4 text-red-700" aria-hidden="true" />
                )}
                <span>
                  {!scopeResult.valid
                    ? 'Erreur de validation'
                    : scopeResult.inScope
                      ? 'Cible autorisée'
                      : 'Hors périmètre bloqué'}
                </span>
              </div>
              <p className="mt-2 text-sm leading-relaxed">{scopeResult.message}</p>
              {scopeResult.matchedVlan && (
                <p className="mt-3 font-mono text-xs opacity-80">
                  Passerelle : {scopeResult.matchedVlan.gateway} · Sous-réseau : {scopeResult.matchedVlan.cidr}
                </p>
              )}
            </div>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center justify-between gap-4 border-t border-slate-200 pt-4">
          <p className="text-xs text-slate-600">
            Étape suivante : Analyser les scans Nmap, les captures Wireshark en clair et le coffre de preuves datées.
          </p>
          <button
            type="button"
            onClick={() => onNavigateToSection('recon')}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-blue-700 hover:text-blue-800 focus-visible:outline-2 focus-visible:outline-blue-700"
          >
            <span>Ouvrir Recon &amp; Preuves</span>
            <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </section>
    </div>
  );
}
