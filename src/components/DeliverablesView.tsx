import { useState } from 'react';
import { CheckCircle2, ChevronDown, ChevronUp, Download, FileText } from 'lucide-react';
import type {
  EvidenceArtifact,
  Finding,
  ScanDiffSummary,
  StakeholderRole,
  VivaQuestion,
  VlanSegment,
} from '../types/assessment';
import { generateAssessmentMarkdown } from '../utils/networkParser';

interface DeliverablesViewProps {
  vlans: VlanSegment[];
  findings: Finding[];
  artifacts: EvidenceArtifact[];
  scanDiff: ScanDiffSummary;
  vivaQuestions: VivaQuestion[];
  onExportMarkdown: () => void;
  onExportJsonManifest: () => void;
}

export function DeliverablesView({
  vlans,
  findings,
  artifacts,
  scanDiff,
  vivaQuestions,
  onExportMarkdown,
  onExportJsonManifest,
}: DeliverablesViewProps) {
  const [roleView, setRoleView] = useState<StakeholderRole>('executive');
  const [expandedViva, setExpandedViva] = useState<string | null>(vivaQuestions[0]?.id ?? null);

  const openFindings = findings.filter((f) => f.status === 'Open');
  const criticalHighOpen = openFindings.filter(
    (f) => f.severity === 'Critical' || f.severity === 'High',
  );
  const remediatedCount = findings.filter((f) => f.status === 'Remediated').length;

  const deliverablesChecklist = [
    {
      name: 'Architecture du lab & périmètre autorisé',
      evidence: `${vlans.length} VLAN segmentés dans 10.20.0.0/16 avec blocage strict hors périmètre`,
      ready: true,
    },
    {
      name: 'Preuves de reconnaissance & captures réseau',
      evidence: `${artifacts.length} artefacts datés avec empreintes SHA-256 et masquage des secrets`,
      ready: artifacts.length >= 5,
    },
    {
      name: 'Fiches de constats & cotation CVSS v3.1',
      evidence: `${findings.length} constats documentés avec étapes reproductibles et vecteurs CVSS`,
      ready: findings.length > 0,
    },
    {
      name: 'Notes de remédiation défensive',
      evidence: 'Diffs Avant/Après nftables, Redis, SSH, Nginx TLS 1.3 et signature SMBv3',
      ready: remediatedCount > 0,
    },
    {
      name: 'Synthèse & validation du contre-audit',
      evidence: `${remediatedCount}/${findings.length} corrigés · réduction de ${scanDiff.reductionPercent} % des ports exposés`,
      ready: criticalHighOpen.length === 0,
    },
  ];

  const previewMarkdown = generateAssessmentMarkdown({
    vlans,
    findings,
    artifacts,
    diff: scanDiff,
    generatedDate: '2026-11-17',
  });

  return (
    <div className="space-y-8">
      {/* Bascule Décideur / Mentor Technique */}
      <section aria-labelledby="stakeholder-brief-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="stakeholder-brief-heading" className="font-display text-lg font-semibold text-slate-900">
              Synthèse Décideur &amp; Revue Technique
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Basculez entre la vue Décideur (bascule en production) et la vue Mentor technique (reproductibilité).
            </p>
          </div>

          <div role="group" aria-label="Sélecteur de rôle" className="inline-flex rounded-lg bg-slate-100 p-1 self-start sm:self-auto">
            <button
              type="button"
              onClick={() => setRoleView('executive')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap shrink-0 ${
                roleView === 'executive'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Décideur / Direction
            </button>
            <button
              type="button"
              onClick={() => setRoleView('technical')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap shrink-0 ${
                roleView === 'technical'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Mentor Technique
            </button>
          </div>
        </div>

        {roleView === 'executive' ? (
          <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="space-y-3 lg:col-span-8">
              <h3 className="text-sm font-semibold text-slate-900">
                Recommandation de bascule :{' '}
                <span className={criticalHighOpen.length === 0 ? 'text-emerald-700' : 'text-red-700'}>
                  {criticalHighOpen.length === 0
                    ? openFindings.length === 0
                      ? 'Approuvée — Tous les constats sont corrigés'
                      : 'Approbation conditionnelle — Zéro risque Critique/Élevé actif'
                    : 'Bloquée — Risques Critiques/Élevés encore ouverts'}
                </span>
              </h3>
              <p className="text-sm leading-relaxed text-slate-600">
                L’évaluation du laboratoire isolé a supprimé tous les chemins latéraux critiques entre la DMZ (VLAN 10) et le stockage de données (VLAN 30), éliminé les protocoles en clair Telnet/HTTP et confirmé une réduction de {scanDiff.reductionPercent} % des ports joignables.{' '}
                {openFindings.length > 0
                  ? `${openFindings.length} point résiduel Faible/Moyen (${openFindings.map((f) => f.id).join(', ')}) reste planifié pour la prochaine fenêtre de maintenance.`
                  : 'Tous les constats enregistrés ont validé le contre-audit.'}
              </p>
            </div>
            <div className="border-t border-slate-200 pt-4 text-xs lg:col-span-4 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-6">
              <p className="font-semibold text-slate-900">Bénéfice métier mesurable</p>
              <ul className="mt-2 space-y-1.5 text-slate-600">
                <li>· Joignabilité directe BDD/SMB depuis la DMZ ramenée de 100 % à 0 %</li>
                <li>· Risque d’interception d’identifiants en clair éliminé sur VLAN 10/20</li>
                <li>· Piste d’audit Nmap + PCAP reproductible prête pour la conformité</li>
              </ul>
            </div>
          </div>
        ) : (
          <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="space-y-3 lg:col-span-8">
              <h3 className="text-sm font-semibold text-slate-900">
                Synthèse de Reproductibilité Technique &amp; Qualité
              </h3>
              <p className="text-sm leading-relaxed text-slate-600">
                Chaque constat du registre s’appuie sur les commandes exactes <span className="font-mono">nmap -sS -sV</span> et <span className="font-mono">tshark</span> archivées dans des dossiers datés avec empreintes SHA-256. Les garde-fous du parseur appliquent strictement le périmètre <span className="font-mono">10.20.0.0/16</span> et traitent les hôtes injoignables, ports filtrés et entrées malformées.
              </p>
            </div>
            <div className="border-t border-slate-200 pt-4 text-xs lg:col-span-4 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-6">
              <p className="font-semibold text-slate-900">Contrôles qualité actifs</p>
              <ul className="mt-2 space-y-1.5 text-slate-600">
                <li>· Calcul déterministe des vecteurs CVSS v3.1</li>
                <li>· Anonymisation des secrets appliquée aux trames PCAP</li>
                <li>· Validation CIDR et moteur de diff testés unitairement</li>
              </ul>
            </div>
          </div>
        )}
      </section>

      {/* Liste de contrôle des livrables */}
      <section aria-labelledby="checklist-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 id="checklist-heading" className="font-display text-lg font-semibold text-slate-900">
          Couverture des Livrables &amp; Critères d’Acceptation
        </h2>
        <div className="mt-4 divide-y divide-slate-200 rounded-md border border-slate-200">
          {deliverablesChecklist.map((item) => (
            <div
              key={item.name}
              className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div>
                <p className="text-sm font-medium text-slate-900">{item.name}</p>
                <p className="text-xs text-slate-600">{item.evidence}</p>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 text-xs font-semibold whitespace-nowrap ${
                  item.ready ? 'text-emerald-700' : 'text-amber-700'
                }`}
              >
                <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                <span>{item.ready ? 'Vérifié & complet' : 'Revue en attente'}</span>
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* Export du dossier complet */}
      <section aria-labelledby="export-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 id="export-heading" className="font-display text-lg font-semibold text-slate-900">
              Exporter le Dossier de Projet Prêt à Présenter
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Généré dynamiquement depuis les constats actifs, scores CVSS, différentiels de scan et manifeste SHA-256.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={onExportMarkdown}
              className="inline-flex items-center gap-2 rounded-md bg-blue-700 px-4 py-2 text-xs font-medium text-white hover:bg-blue-800 whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Télécharger le rapport Markdown</span>
            </button>
            <button
              type="button"
              onClick={onExportJsonManifest}
              className="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              <FileText className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Télécharger le manifeste JSON</span>
            </button>
          </div>
        </div>

        <pre className="mt-4 max-h-72 overflow-auto rounded-md border border-slate-200 bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-200">
          <code>{previewMarkdown}</code>
        </pre>
      </section>

      {/* Préparation soutenance / entretien */}
      <section aria-labelledby="viva-heading" className="rounded-lg border border-slate-200 bg-white p-6">
        <h2 id="viva-heading" className="font-display text-lg font-semibold text-slate-900">
          Préparation Soutenance &amp; Questions d’Entretien
        </h2>
        <div className="mt-4 divide-y divide-slate-200 rounded-md border border-slate-200">
          {vivaQuestions.map((vq) => {
            const isOpen = expandedViva === vq.id;
            return (
              <div key={vq.id}>
                <button
                  type="button"
                  aria-expanded={isOpen}
                  onClick={() => setExpandedViva(isOpen ? null : vq.id)}
                  className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left text-sm font-medium text-slate-900 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-blue-700"
                >
                  <span>{vq.question}</span>
                  {isOpen ? (
                    <ChevronUp className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
                  ) : (
                    <ChevronDown className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
                  )}
                </button>
                {isOpen && (
                  <div className="border-t border-slate-100 bg-slate-50 px-4 py-3 text-sm leading-relaxed text-slate-700">
                    {vq.answer}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
