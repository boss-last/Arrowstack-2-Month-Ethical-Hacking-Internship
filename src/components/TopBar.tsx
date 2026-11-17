import { Download, Menu } from 'lucide-react';
import type { NavSection } from '../types/assessment';

interface TopBarProps {
  activeSection: NavSection;
  onOpenMobileMenu: () => void;
  onExportReport: () => void;
}

const SECTION_TITLES: Record<NavSection, string> = {
  overview: 'Périmètre & Topologie VLAN',
  recon: 'Reconnaissance & Laboratoire de Preuves',
  findings: 'Constats & Cotation CVSS',
  retest: 'Correctifs & Contre-audit',
  deliverables: 'Livrables & Revue Décisionnaire',
};

export function TopBar({
  activeSection,
  onOpenMobileMenu,
  onExportReport,
}: TopBarProps) {
  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-slate-200 bg-white px-4 py-3 sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Ouvrir le menu de navigation"
          className="rounded-md border border-slate-200 p-2 text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 lg:hidden"
        >
          <Menu className="h-4 w-4" aria-hidden="true" />
        </button>

        <nav aria-label="Fil d’Ariane" className="flex min-w-0 items-center gap-2 text-sm">
          <span className="hidden text-slate-500 sm:inline whitespace-nowrap">
            Audits
          </span>
          <span className="hidden text-slate-300 sm:inline" aria-hidden="true">
            /
          </span>
          <span className="hidden font-mono text-xs text-slate-500 md:inline whitespace-nowrap">
            10.20.0.0/16
          </span>
          <span className="hidden text-slate-300 md:inline" aria-hidden="true">
            /
          </span>
          <h1 className="truncate font-display text-sm font-semibold text-slate-900 sm:text-base">
            {SECTION_TITLES[activeSection]}
          </h1>
        </nav>
      </div>

      <div className="flex shrink-0 items-center">
        <button
          type="button"
          onClick={onExportReport}
          className="inline-flex items-center gap-2 rounded-md bg-blue-700 px-4 py-2 text-xs font-medium text-white transition-colors duration-150 hover:bg-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700 whitespace-nowrap shrink-0"
        >
          <Download className="h-3.5 w-3.5" aria-hidden="true" />
          <span>Exporter le rapport</span>
        </button>
      </div>
    </header>
  );
}
