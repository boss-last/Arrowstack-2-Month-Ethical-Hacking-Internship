import { useState, type FormEvent } from 'react';
import { Plus, Search, X } from 'lucide-react';
import type {
  CvssMetrics,
  Finding,
  FindingStatus,
  Severity,
  VlanSegment,
} from '../types/assessment';
import {
  calculateCvssV31,
  formatCategoryFr,
  formatSeverityFr,
  formatStatusFr,
  validateTargetInScope,
} from '../utils/networkParser';

interface FindingsCvssViewProps {
  findings: Finding[];
  vlans: VlanSegment[];
  onAddFinding: (finding: Finding) => void;
  onUpdateFindingCvss: (id: string, metrics: CvssMetrics) => void;
}

function severityColor(severity: Severity): string {
  switch (severity) {
    case 'Critical':
      return 'text-red-700 font-semibold';
    case 'High':
      return 'text-orange-700 font-semibold';
    case 'Medium':
      return 'text-amber-700 font-semibold';
    case 'Low':
      return 'text-blue-700 font-medium';
    default:
      return 'text-slate-600 font-medium';
  }
}

export function FindingsCvssView({
  findings,
  vlans,
  onAddFinding,
  onUpdateFindingCvss,
}: FindingsCvssViewProps) {
  const [severityFilter, setSeverityFilter] = useState<'All' | Severity>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | FindingStatus>('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState<string>(findings[0]?.id ?? '');

  // Modale ajout de constat
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newHostIp, setNewHostIp] = useState('10.20.20.14');
  const [newPort, setNewPort] = useState('8080');
  const [newCategory, setNewCategory] = useState<Finding['category']>('Exposed Service');
  const [newSummary, setNewSummary] = useState('');
  const [newImpact, setNewImpact] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'All' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'All' && f.status !== statusFilter) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      return (
        f.id.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.hostIp.includes(q) ||
        String(f.port ?? '').includes(q)
      );
    }
    return true;
  });

  const activeFinding =
    findings.find((f) => f.id === selectedFindingId) ?? filteredFindings[0] ?? null;

  const handleCreateFinding = (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (newTitle.trim().length < 6) {
      setFormError('Le titre du constat doit contenir au moins 6 caractères.');
      return;
    }

    const scopeCheck = validateTargetInScope(newHostIp, vlans);
    if (!scopeCheck.valid || !scopeCheck.inScope) {
      setFormError(scopeCheck.message);
      return;
    }

    const parsedPort = Number(newPort);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setFormError('Le port doit être un entier TCP/UDP valide entre 1 et 65535.');
      return;
    }

    if (newSummary.trim().length < 12) {
      setFormError('Saisissez un résumé technique (au moins 12 caractères).');
      return;
    }

    const defaultMetrics: CvssMetrics = {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S: 'U',
      C: 'H',
      I: 'L',
      A: 'N',
    };
    const { score, severity, vector } = calculateCvssV31(defaultMetrics);
    const nextNum = findings.length + 1;
    const id = `NET-${String(nextNum).padStart(2, '0')}`;

    const created: Finding = {
      id,
      title: newTitle.trim(),
      hostIp: scopeCheck.normalizedIp,
      vlanName: scopeCheck.matchedVlan?.name ?? 'Lab autorisé',
      port: parsedPort,
      protocol: 'tcp',
      category: newCategory,
      severity,
      cvssScore: score,
      cvssVector: vector,
      cvssMetrics: defaultMetrics,
      status: 'Open',
      summary: newSummary.trim(),
      businessImpact:
        newImpact.trim() || 'Augmente la surface d’attaque latérale entre segments du laboratoire.',
      reproducibleSteps: [
        `Vérifier le périmètre et scanner le port ${parsedPort}/tcp : nmap -sV -p ${parsedPort} ${scopeCheck.normalizedIp}`,
        'Capturer la bannière ou négociation protocolaire avec Wireshark/tshark.',
      ],
      evidenceRef: `2026-11-17_adhoc/nmap_${scopeCheck.normalizedIp}.txt`,
      remediationSummary: 'Restreindre l’accès via ACL nftables et désactiver le service superflu.',
      configBefore: `# Port ${parsedPort}/tcp en écoute sur 0.0.0.0`,
      configAfter: `ufw deny ${parsedPort}/tcp`,
      retestCommand: `nmap -sS -p ${parsedPort} ${scopeCheck.normalizedIp}`,
      retestOutput: 'En attente de contre-audit.',
      retestVerifiedDate: null,
    };

    onAddFinding(created);
    setSelectedFindingId(created.id);
    setNewTitle('');
    setNewSummary('');
    setNewImpact('');
    setIsAddOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Barre de filtres */}
      <section aria-label="Filtres des constats" className="rounded-lg border border-slate-200 bg-white p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative w-full sm:w-64">
              <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-slate-400" aria-hidden="true" />
              <input
                type="text"
                aria-label="Rechercher un constat"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Rechercher ID, IP, port, titre..."
                className="w-full rounded-md border border-slate-300 bg-white py-2 pr-3 pl-9 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
              />
            </div>

            <div role="group" aria-label="Filtre par sévérité" className="inline-flex rounded-lg bg-slate-100 p-1">
              {(['All', 'Critical', 'High', 'Medium', 'Low'] as const).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium whitespace-nowrap shrink-0 ${
                    severityFilter === sev
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {sev === 'All' ? 'Toutes' : formatSeverityFr(sev)}
                </button>
              ))}
            </div>

            <div role="group" aria-label="Filtre par statut" className="inline-flex rounded-lg bg-slate-100 p-1">
              {(['All', 'Open', 'Remediated'] as const).map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium whitespace-nowrap shrink-0 ${
                    statusFilter === st
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {st === 'All' ? 'Tous' : formatStatusFr(st)}
                </button>
              ))}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setIsAddOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3.5 py-2 text-xs font-medium text-white hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-slate-900 whitespace-nowrap shrink-0 self-start lg:self-auto"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Ajouter un constat</span>
          </button>
        </div>
      </section>

      {/* Vue Maître-Détail */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <section aria-label="Registre des constats" className="xl:col-span-6">
          <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 font-medium text-slate-600">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Constat &amp; Cible</th>
                  <th className="px-4 py-3 text-right">CVSS</th>
                  <th className="px-4 py-3">Statut</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-sm text-slate-500">
                      Aucun constat ne correspond aux filtres actifs.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((f) => {
                    const isSelected = activeFinding?.id === f.id;
                    return (
                      <tr
                        key={f.id}
                        className={`transition-colors ${
                          isSelected ? 'bg-blue-50/70' : 'hover:bg-slate-50'
                        }`}
                      >
                        <td className="px-4 py-3 font-mono font-semibold text-slate-900 whitespace-nowrap">
                          {f.id}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={() => setSelectedFindingId(f.id)}
                            className="text-left font-medium text-slate-900 hover:text-blue-700 hover:underline focus-visible:outline-2 focus-visible:outline-blue-700"
                          >
                            {f.title}
                          </button>
                          <div className="mt-1 font-mono text-slate-500 tabular-nums">
                            {f.hostIp} {f.port ? `:${f.port}` : ''} · {formatCategoryFr(f.category)}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-right whitespace-nowrap">
                          <div className={`font-mono tabular-nums ${severityColor(f.severity)}`}>
                            {f.cvssScore.toFixed(1)}
                          </div>
                          <div className="text-slate-500">{formatSeverityFr(f.severity)}</div>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={
                              f.status === 'Remediated'
                                ? 'font-medium text-emerald-700'
                                : 'font-semibold text-amber-700'
                            }
                          >
                            {formatStatusFr(f.status)}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Fiche technique & Calculateur CVSS v3.1 */}
        <section aria-label="Fiche technique du constat" className="xl:col-span-6">
          {activeFinding ? (
            <div className="space-y-6 rounded-lg border border-slate-200 bg-white p-6">
              <div className="border-b border-slate-200 pb-4">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                  <span className="font-mono font-semibold text-slate-900">
                    {activeFinding.id} · {activeFinding.hostIp}
                    {activeFinding.port ? `:${activeFinding.port}/${activeFinding.protocol}` : ''}
                  </span>
                  <span className={severityColor(activeFinding.severity)}>
                    {formatSeverityFr(activeFinding.severity)} · CVSS {activeFinding.cvssScore.toFixed(1)} · {formatStatusFr(activeFinding.status)}
                  </span>
                </div>
                <h2 className="mt-2 font-display text-lg font-semibold text-slate-900">
                  {activeFinding.title}
                </h2>
                <p className="mt-1 font-mono text-xs text-slate-500">
                  {activeFinding.vlanName} · Preuve : {activeFinding.evidenceRef}
                </p>
              </div>

              <div className="space-y-4 text-sm">
                <div>
                  <h3 className="text-xs font-semibold text-slate-900">Résumé technique</h3>
                  <p className="mt-1 leading-relaxed text-slate-600">{activeFinding.summary}</p>
                </div>

                <div>
                  <h3 className="text-xs font-semibold text-slate-900">Impact métier &amp; segmentation</h3>
                  <p className="mt-1 leading-relaxed text-slate-600">{activeFinding.businessImpact}</p>
                </div>

                <div>
                  <h3 className="text-xs font-semibold text-slate-900">Étapes reproductibles</h3>
                  <ol className="mt-1.5 list-decimal space-y-1.5 pl-5 text-xs leading-relaxed text-slate-700">
                    {activeFinding.reproducibleSteps.map((step, i) => (
                      <li key={i} className="font-mono">
                        {step}
                      </li>
                    ))}
                  </ol>
                </div>
              </div>

              {/* Calculateur CVSS v3.1 interactif */}
              <div className="border-t border-slate-200 pt-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-xs font-semibold text-slate-900">
                    Simulateur interactif de score CVSS v3.1
                  </h3>
                  <code className="font-mono text-xs text-slate-600">{activeFinding.cvssVector}</code>
                </div>

                <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <label className="block text-xs text-slate-600">
                    <span>Vecteur d’attaque</span>
                    <select
                      value={activeFinding.cvssMetrics.AV}
                      onChange={(e) =>
                        onUpdateFindingCvss(activeFinding.id, {
                          ...activeFinding.cvssMetrics,
                          AV: e.target.value as CvssMetrics['AV'],
                        })
                      }
                      className="mt-1 w-full rounded border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900"
                    >
                      <option value="N">Réseau (N)</option>
                      <option value="A">Adjacent (A)</option>
                      <option value="L">Local (L)</option>
                    </select>
                  </label>

                  <label className="block text-xs text-slate-600">
                    <span>Complexité</span>
                    <select
                      value={activeFinding.cvssMetrics.AC}
                      onChange={(e) =>
                        onUpdateFindingCvss(activeFinding.id, {
                          ...activeFinding.cvssMetrics,
                          AC: e.target.value as CvssMetrics['AC'],
                        })
                      }
                      className="mt-1 w-full rounded border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900"
                    >
                      <option value="L">Faible (L)</option>
                      <option value="H">Élevée (H)</option>
                    </select>
                  </label>

                  <label className="block text-xs text-slate-600">
                    <span>Privilèges</span>
                    <select
                      value={activeFinding.cvssMetrics.PR}
                      onChange={(e) =>
                        onUpdateFindingCvss(activeFinding.id, {
                          ...activeFinding.cvssMetrics,
                          PR: e.target.value as CvssMetrics['PR'],
                        })
                      }
                      className="mt-1 w-full rounded border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900"
                    >
                      <option value="N">Aucun (N)</option>
                      <option value="L">Faibles (L)</option>
                      <option value="H">Élevés (H)</option>
                    </select>
                  </label>

                  <label className="block text-xs text-slate-600">
                    <span>Portée (Scope)</span>
                    <select
                      value={activeFinding.cvssMetrics.S}
                      onChange={(e) =>
                        onUpdateFindingCvss(activeFinding.id, {
                          ...activeFinding.cvssMetrics,
                          S: e.target.value as CvssMetrics['S'],
                        })
                      }
                      className="mt-1 w-full rounded border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-900"
                    >
                      <option value="U">Inchangée (U)</option>
                      <option value="C">Modifiée (C)</option>
                    </select>
                  </label>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-slate-200 bg-white p-8 text-center text-sm text-slate-500">
              Sélectionnez un constat dans le registre pour afficher ses preuves et son vecteur CVSS.
            </div>
          )}
        </section>
      </div>

      {/* Modale d’ajout de constat */}
      {isAddOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="add-finding-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
        >
          <div className="w-full max-w-lg rounded-lg border border-slate-200 bg-white p-6 shadow-lg">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h2 id="add-finding-title" className="font-display text-base font-semibold text-slate-900">
                Enregistrer un Nouveau Constat
              </h2>
              <button
                type="button"
                onClick={() => setIsAddOpen(false)}
                aria-label="Fermer la fenêtre"
                className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>

            <form onSubmit={handleCreateFinding} className="mt-4 space-y-4">
              {formError && (
                <div role="alert" className="rounded border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
                  {formError}
                </div>
              )}

              <div>
                <label htmlFor="finding-title-input" className="block text-xs font-medium text-slate-700">
                  Intitulé du constat
                </label>
                <input
                  id="finding-title-input"
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="ex. Point d’accès métriques Gunicorn non chiffré"
                  className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-blue-600 focus-visible:outline-2 focus-visible:outline-blue-600"
                />
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                  <label htmlFor="finding-ip-input" className="block text-xs font-medium text-slate-700">
                    IP cible autorisée
                  </label>
                  <input
                    id="finding-ip-input"
                    type="text"
                    value={newHostIp}
                    onChange={(e) => setNewHostIp(e.target.value)}
                    className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm text-slate-900"
                  />
                </div>

                <div>
                  <label htmlFor="finding-port-input" className="block text-xs font-medium text-slate-700">
                    Port
                  </label>
                  <input
                    id="finding-port-input"
                    type="text"
                    value={newPort}
                    onChange={(e) => setNewPort(e.target.value)}
                    className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm text-slate-900"
                  />
                </div>

                <div>
                  <label htmlFor="finding-cat-select" className="block text-xs font-medium text-slate-700">
                    Catégorie
                  </label>
                  <select
                    id="finding-cat-select"
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value as Finding['category'])}
                    className="mt-1 w-full rounded-md border border-slate-300 bg-white px-2.5 py-2 text-sm text-slate-900"
                  >
                    <option value="Exposed Service">Service exposé</option>
                    <option value="Weak Configuration">Configuration faible</option>
                    <option value="Segmentation Gap">Faille de segmentation</option>
                    <option value="Cleartext Traffic">Trafic en clair</option>
                  </select>
                </div>
              </div>

              <div>
                <label htmlFor="finding-summary-input" className="block text-xs font-medium text-slate-700">
                  Résumé technique
                </label>
                <textarea
                  id="finding-summary-input"
                  rows={3}
                  value={newSummary}
                  onChange={(e) => setNewSummary(e.target.value)}
                  placeholder="Décrivez le port exposé, la faiblesse protocolaire et sa vérification..."
                  className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
                />
              </div>

              <div>
                <label htmlFor="finding-impact-input" className="block text-xs font-medium text-slate-700">
                  Impact métier / segmentation (optionnel)
                </label>
                <input
                  id="finding-impact-input"
                  type="text"
                  value={newImpact}
                  onChange={(e) => setNewImpact(e.target.value)}
                  placeholder="Précisez le risque de rebond ou d’interception"
                  className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-900"
                />
              </div>

              <div className="flex justify-end gap-3 border-t border-slate-200 pt-4">
                <button
                  type="button"
                  onClick={() => setIsAddOpen(false)}
                  className="rounded-md border border-slate-300 bg-white px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  className="rounded-md bg-blue-700 px-4 py-2 text-xs font-medium text-white hover:bg-blue-800"
                >
                  Enregistrer
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
