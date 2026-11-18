# NetScope Lab — Laboratoire d’Audit de Sécurité Réseau

> **Projet 2 : Network Security Assessment Lab**  
> Banc d’évaluation et de restitution en sécurité réseau sur laboratoire isolé (`10.20.0.0/16`), couvrant le cadrage du périmètre, la reconnaissance Nmap/Wireshark, la cotation CVSS v3.1, la remédiation défensive et le contre-audit Avant/Après.

---

## 1. Contexte, Objectif & Cas d’Usage Métier

### Scénario
Évaluer un réseau de laboratoire isolé découpé en quatre VLAN afin d’identifier les services inutilement exposés, les protocoles en clair, les configurations faibles et les ruptures de segmentation, puis documenter et vérifier les correctifs défensifs par contre-audit.

### Cadrage décisionnel
- **Partie prenante principale :** Responsable Infrastructure & SecOps
- **Décision permise :** Autoriser ou bloquer la bascule d’un environnement segmenté vers la production et valider la politique de pare-feu inter-VLAN.
- **Bénéfices mesurables constatés après remédiation :**
  - **-75 % de surface TCP exposée** (`12` ports ouverts initiaux $\rightarrow$ `3` ports autorisés au contre-audit).
  - **0 constat Critique ou Élevé ouvert** (`4` risques Critiques/Élevés corrigés et retestés).
  - **0 chemin latéral direct** entre la DMZ (`VLAN 10`) et le stockage de données (`VLAN 30`).
  - **0 protocole en clair** en transit (suppression de Telnet, HTTP admin sans TLS, Redis sans authentification et SMBv1).

### Contraintes & Critères de succès
- **Périmètre strictement autorisé :** uniquement le bloc privé de laboratoire `10.20.0.0/16`. Toute adresse IP publique ou externe est explicitement bloquée par le garde-fou applicatif.
- **Confidentialité & intégrité des preuves :** masquage des identifiants capturés (`[REDACTED]`) et vérification par empreintes `SHA-256` dans des dossiers de preuves datés.

---

## 2. Architecture du Laboratoire Isolé (`10.20.0.0/16`)

| VLAN | Nom | Sous-réseau CIDR | Passerelle | Zone de confiance | Hôtes principaux |
| --- | --- | --- | --- | --- | --- |
| `10` | Zone DMZ | `10.20.10.0/24` | `10.20.10.1` | Non fiable | `edge-gw-01.lab` (`10.20.10.10`) |
| `20` | Tier Applicatif | `10.20.20.0/24` | `10.20.20.1` | Confiance partielle | `app-api-01.lab` (`10.20.20.14`), `cache-01.lab` (`10.20.20.18`) |
| `30` | Données & Stockage | `10.20.30.0/24` | `10.20.30.1` | Restreinte | `db-core-01.lab` (`10.20.30.11`), `fileshare-01.lab` (`10.20.30.15`) |
| `99` | Administration | `10.20.99.0/24` | `10.20.99.1` | Admin isolée | `bastion-01.lab` (`10.20.99.5`) |

---

## 3. Fonctionnalités & Modules de l’Application

1. **Périmètre & Topologie (`Scope & Topology`)**
   - Cadrage du problème, indicateurs comparatifs Avant/Après et matrice de filtrage inter-VLAN.
   - Bascule interactive entre l’état initial (`2026-11-10`) et l’état durci (`2026-11-16`).
   - **Garde-fou IPv4/CIDR en direct** : valide la syntaxe IPv4, associe la cible au VLAN correspondant et bloque toute IP hors périmètre (ex. `8.8.8.8`) ou malformée (ex. `10.20.999.4`).

2. **Reconnaissance & Preuves (`Recon & Evidence`)**
   - **Analyseur Nmap automatisé (`-oN` et `-oG`)** : extrait hôtes, ports, bannières et évalue le niveau de risque (`Telnet`, `Redis sans auth`, `SMBv1`, `MySQL`, `HTTP`, `SSH`). Gère les cas limites (hôte injoignable `Host seems down`, ports `filtered`, entrées vides ou malformées) et permet de promouvoir un port exposé directement en constat.
   - **Inspecteur de captures Wireshark (`.pcapng`)** : filtrage par phase (initiale vs contre-audit), protocole et alertes en clair avec anonymisation des secrets.
   - **Dossier de preuves datées** : `2026-11-10_baseline/`, `2026-11-14_remediation/`, `2026-11-16_retest/` avec commandes CLI reproductibles et empreintes `SHA-256`.

3. **Constats & Cotation CVSS v3.1 (`Findings & CVSS`)**
   - Registre filtrable par sévérité, statut et recherche textuelle.
   - Fiches détaillées (`NET-01` à `NET-06` + constats ajoutés/promus) avec étapes reproductibles et **simulateur interactif de score CVSS v3.1** (recalcul temps réel du score et du vecteur).
   - Formulaire validé d’ajout de constat (contrôle de périmètre et de plage de port `1–65535`).

4. **Correctifs & Contre-Audit (`Remediation & Retest`)**
   - Calcul automatique du différentiel Nmap Avant/Après (`diffScans`).
   - Comparatifs de configuration **Avant / Après** copiables (`nftables`, `redis.conf`, suppression `telnetd`, désactivation `SMBv1` + signature `SMBv3`, `Nginx TLS 1.3 + HSTS`, `sshd_config`).
   - Validation interactive du statut de contre-audit et tableau des limites + feuille de route à l’échelle `10×`.

5. **Livrables & Revue (`Deliverables & Review`)**
   - Bascule de point de vue **Décideur / Direction** vs **Mentor Technique**.
   - Liste de contrôle dynamique des livrables et critères d’acceptation.
   - Export complet en **Rapport Markdown (`.md`)** et **Manifeste JSON (`.json`)**, accompagné des réponses de préparation à la soutenance (Viva).

---

## 4. Structure du Projet

```text
├── index.html                        # Point d’entrée HTML (lang="fr", polices Google Fonts)
├── metadata.json                     # Métadonnées de l’application
├── package.json                      # Dépendances et scripts npm
├── vite.config.ts                    # Configuration Vite + Tailwind v4
└── src/
    ├── App.tsx                       # Orchestrateur d’état et navigation entre vues
    ├── index.css                     # Styles globaux Tailwind CSS v4
    ├── types/
    │   └── assessment.ts             # Contrats TypeScript (VLAN, Nmap, PCAP, CVSS, Constats)
    ├── utils/
    │   ├── networkParser.ts          # Validation CIDR, parseur Nmap, diff, CVSS v3.1, export MD
    │   └── networkParser.test.ts     # Tests unitaires (node:test)
    ├── data/
    │   └── labDataset.ts             # Jeu de données complet du laboratoire (scans, trames, constats)
    └── components/
        ├── Sidebar.tsx               # Navigation latérale
        ├── TopBar.tsx                # Fil d’Ariane et action d’export rapide
        ├── OverviewScopeView.tsx     # Cadrage, topologie VLAN et validateur de périmètre
        ├── ReconEvidenceView.tsx     # Analyseur Nmap, inspecteur PCAP et coffre de preuves
        ├── FindingsCvssView.tsx      # Registre des constats, calculateur CVSS et modale d’ajout
        ├── RemediationRetestView.tsx # Diff Avant/Après, configurations durcies et feuille de route
        └── DeliverablesView.tsx      # Vue Décideur/Mentor, exports et préparation soutenance
```

---

## 5. Installation, Lancement & Tests (Reproductibilité)

### Prérequis
- Node.js `>= 20` et `npm`

### Commandes

```bash
# 1. Installer les dépendances
npm install

# 2. Lancer le serveur de développement (port 3000)
npm run dev

# 3. Exécuter les tests unitaires de la logique réseau et CVSS
npx --yes tsx --test src/utils/networkParser.test.ts

# 4. Vérifier le typage TypeScript et générer le build de production
npm run lint
npm run build
```

---

## 6. Limites Documentées & Améliorations Futures

- **Pont virtuel vs commutation L2 physique :** les règles `nftables` valident l’isolation L3/L4 en laboratoire virtuel ; en production, elles doivent être complétées par des contrôles L2 matériels (DAI, DHCP Snooping, port-security).
- **Périmètre boîte noire sans agent :** compléter l’audit d’exposition réseau par des audits de conformité système authentifiés (`Ansible` / `OpenSCAP` selon les benchmarks CIS).
- **Passage à l’échelle 10× :** remplacer les captures manuelles par des sondes `Nmap XML` automatisées en CI/CD remontant toute dérive de port ouvert vers un SIEM centralisé.
