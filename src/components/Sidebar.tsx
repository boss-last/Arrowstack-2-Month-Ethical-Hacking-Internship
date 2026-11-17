import {
  ShieldCheck,
  Radar,
  FileWarning,
  GitCompare,
  ClipboardCheck,
  X,
} from 'lucide-react';
import type { NavSection } from '../types/assessment';

interface SidebarProps {
  activeSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  openFindingCount: number;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

const NAV_ITEMS: Array<{
  id: NavSection;
  label: string;
  icon: typeof ShieldCheck;
}> = [
  { id: 'overview', label: 'Périmètre & Topologie', icon: ShieldCheck },
  { id: 'recon', label: 'Recon & Preuves', icon: Radar },
  { id: 'findings', label: 'Constats & CVSS', icon: FileWarning },
  { id: 'retest', label: 'Correctifs & Contre-audit', icon: GitCompare },
  { id: 'deliverables', label: 'Livrables & Revue', icon: ClipboardCheck },
];

export function Sidebar({
  activeSection,
  onSelectSection,
  openFindingCount,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const navContent = (
    <div className="flex h-full flex-col justify-between bg-slate-900 text-slate-100">
      <div>
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <span className="font-display text-base font-semibold tracking-tight text-white whitespace-nowrap shrink-0">
            NetScope Lab
          </span>
          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Fermer le menu de navigation"
            className="rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 lg:hidden"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <nav aria-label="Navigation de l’audit" className="px-3 py-4">
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = activeSection === item.id;
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    onClick={() => {
                      onSelectSection(item.id);
                      onCloseMobile();
                    }}
                    aria-current={isActive ? 'page' : undefined}
                    className={`flex w-full items-center justify-between rounded-md px-3 py-2.5 text-left text-sm font-medium transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 whitespace-nowrap ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                    }`}
                  >
                    <span className="flex items-center gap-2.5 truncate">
                      <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                      <span className="truncate">{item.label}</span>
                    </span>
                    {item.id === 'findings' && (
                      <span
                        className={`font-mono text-xs tabular-nums ${
                          isActive ? 'text-blue-100' : 'text-slate-400'
                        }`}
                      >
                        {openFindingCount} ouv.
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>
      </div>

      <div className="border-t border-slate-800 px-5 py-4 text-xs text-slate-400">
        <p className="font-medium text-slate-200">Laboratoire Autorisé</p>
        <p className="mt-1 font-mono tabular-nums text-slate-400">10.20.0.0/16 · 4 VLAN</p>
        <p className="mt-1 text-slate-500">Environnement isolé uniquement</p>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden w-62 shrink-0 border-r border-slate-200 lg:block">
        <div className="sticky top-0 h-screen">{navContent}</div>
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden" role="dialog" aria-modal="true" aria-label="Menu de navigation">
          <div
            className="fixed inset-0 bg-slate-900/50"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <div className="relative z-10 w-64 max-w-[80vw]">{navContent}</div>
        </div>
      )}
    </>
  );
}
