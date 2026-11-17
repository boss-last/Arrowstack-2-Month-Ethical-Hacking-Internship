import type {
  EvidenceArtifact,
  Finding,
  LabHost,
  LimitationItem,
  PacketFrame,
  SegmentationRule,
  VivaQuestion,
} from '../types/assessment';
import { calculateCvssV31 } from '../utils/networkParser';

export const LAB_HOSTS: LabHost[] = [
  {
    ip: '10.20.10.10',
    hostname: 'edge-gw-01.lab',
    vlanId: 'vlan-10',
    os: 'Ubuntu 24.04 LTS (Linux 6.8)',
    role: 'Reverse Proxy Nginx & Entrée DMZ',
    baselineOpenPorts: [22, 80, 443],
    retestOpenPorts: [443],
  },
  {
    ip: '10.20.20.14',
    hostname: 'app-api-01.lab',
    vlanId: 'vlan-20',
    os: 'Debian 12 (Linux 6.1)',
    role: 'API REST interne & Shell d’admin hérité',
    baselineOpenPorts: [22, 23, 8080],
    retestOpenPorts: [8443],
  },
  {
    ip: '10.20.20.18',
    hostname: 'cache-01.lab',
    vlanId: 'vlan-20',
    os: 'Alpine Linux 3.20',
    role: 'Broker de cache de session et file d’attente',
    baselineOpenPorts: [6379],
    retestOpenPorts: [],
  },
  {
    ip: '10.20.30.11',
    hostname: 'db-core-01.lab',
    vlanId: 'vlan-30',
    os: 'Ubuntu 22.04 LTS',
    role: 'Base de données relationnelle principale',
    baselineOpenPorts: [22, 3306],
    retestOpenPorts: [],
  },
  {
    ip: '10.20.30.15',
    hostname: 'fileshare-01.lab',
    vlanId: 'vlan-30',
    os: 'Windows Server 2019 Lab VM',
    role: 'Archive documentaire interne',
    baselineOpenPorts: [139, 445],
    retestOpenPorts: [445],
  },
  {
    ip: '10.20.99.5',
    hostname: 'bastion-01.lab',
    vlanId: 'vlan-99',
    os: 'Debian 12 Hardened',
    role: 'Bastion d’administration isolé',
    baselineOpenPorts: [22],
    retestOpenPorts: [22],
  },
];

export const SEGMENTATION_RULES: SegmentationRule[] = [
  {
    sourceVlanId: 'vlan-10',
    destVlanId: 'vlan-20',
    baselineState: 'Unrestricted',
    baselineDetail: 'Tout hôte de la DMZ peut joindre TCP/23, TCP/6379 et TCP/8080 sur le VLAN 20.',
    retestState: 'TLS/Restricted',
    retestDetail: 'Seul edge-gw-01 (10.20.10.10) est autorisé vers app-api-01 TCP/8443 en mTLS.',
  },
  {
    sourceVlanId: 'vlan-10',
    destVlanId: 'vlan-30',
    baselineState: 'Permissive',
    baselineDetail: 'Routage direct DMZ permis vers db-core-01 (3306) et fileshare-01 (445).',
    retestState: 'Blocked',
    retestDetail: 'ACL de refus par défaut bloquant tout trafic DMZ vers Données (journalisé syslog).',
  },
  {
    sourceVlanId: 'vlan-20',
    destVlanId: 'vlan-30',
    baselineState: 'Unrestricted',
    baselineDetail: 'Tous les hôtes VLAN 20 peuvent sonder SMB (445) et MySQL (3306) sans ACL.',
    retestState: 'TLS/Restricted',
    retestDetail: 'Seul app-api-01 accède à db-core-01 TCP/3306 ; SMB (445) refusé depuis VLAN 20.',
  },
  {
    sourceVlanId: 'vlan-10',
    destVlanId: 'vlan-99',
    baselineState: 'Permissive',
    baselineDetail: 'SSH (22) joignable depuis l’interface DMZ sur bastion-01.',
    retestState: 'Blocked',
    retestDetail: 'Entrée SSH bloquée depuis la DMZ ; accès admin restreint au VPN + VLAN 99.',
  },
];

export const BASELINE_NMAP_OUTPUT = `# Nmap 7.95 scan initiated 2026-11-10 09:15 UTC as: nmap -sS -sV -O -p 21,22,23,80,139,443,445,3306,6379,8080,8443 -oN 2026-11-10_baseline/nmap_full.txt 10.20.0.0/16
Nmap scan report for edge-gw-01.lab (10.20.10.10)
Host is up (0.00084s latency).
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu (password auth enabled)
80/tcp   open  http     nginx 1.24.0
443/tcp  open  ssl/http nginx 1.24.0

Nmap scan report for app-api-01.lab (10.20.20.14)
Host is up (0.0011s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian
23/tcp   open  telnet     Linux telnetd
8080/tcp open  http-proxy Gunicorn 21.2.0

Nmap scan report for cache-01.lab (10.20.20.18)
Host is up (0.00095s latency).
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 7.0.11 (unauthenticated)

Nmap scan report for db-core-01.lab (10.20.30.11)
Host is up (0.0014s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
3306/tcp open  mysql   MySQL 8.0.35

Nmap scan report for fileshare-01.lab (10.20.30.15)
Host is up (0.0019s latency).
PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2019 (SMBv1 enabled)

Nmap scan report for bastion-01.lab (10.20.99.5)
Host is up (0.00061s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian`;

export const RETEST_NMAP_OUTPUT = `# Nmap 7.95 scan initiated 2026-11-16 14:20 UTC from DMZ probe (10.20.10.50) as: nmap -sS -sV -p 21,22,23,80,139,443,445,3306,6379,8080,8443 -oN 2026-11-16_retest/nmap_retest.txt 10.20.0.0/16
Nmap scan report for edge-gw-01.lab (10.20.10.10)
Host is up (0.00079s latency).
PORT     STATE    SERVICE  VERSION
22/tcp   filtered ssh
80/tcp   closed   http
443/tcp  open     ssl/http nginx 1.24.0 (TLSv1.3)

Nmap scan report for app-api-01.lab (10.20.20.14)
Host is up (0.0012s latency).
PORT     STATE    SERVICE    VERSION
22/tcp   filtered ssh
23/tcp   closed   telnet
8080/tcp closed   http-proxy
8443/tcp open     ssl/https  Gunicorn TLS proxy

Nmap scan report for cache-01.lab (10.20.20.18)
Host is up (0.00091s latency).
PORT     STATE    SERVICE VERSION
6379/tcp filtered redis

Nmap scan report for db-core-01.lab (10.20.30.11)
Host is up (0.0015s latency).
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
3306/tcp filtered mysql

Nmap scan report for fileshare-01.lab (10.20.30.15)
Host is up (0.0018s latency).
PORT    STATE    SERVICE      VERSION
139/tcp closed   netbios-ssn
445/tcp filtered microsoft-ds

Nmap scan report for bastion-01.lab (10.20.99.5)
Host is up (0.00058s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian (key-only + MFA)`;

export const PACKET_FRAMES: PacketFrame[] = [
  {
    frameNumber: 14,
    timestamp: '00:00:04.118',
    sourceIp: '10.20.10.50',
    destIp: '10.20.20.14',
    protocol: 'TELNET',
    length: 94,
    info: 'Telnet Data: login: ops_admin / Password: [REDACTED]',
    capturePhase: 'baseline',
    cleartextAlert: true,
    decodedSummary:
      'Flux TCP 2 (10.20.10.50:54112 -> 10.20.20.14:23) : Session Telnet non chiffrée capturant les octets d’authentification en clair. Identifiants masqués avant archivage.',
    redactionApplied: true,
  },
  {
    frameNumber: 39,
    timestamp: '00:00:11.602',
    sourceIp: '10.20.10.50',
    destIp: '10.20.10.10',
    protocol: 'HTTP',
    length: 218,
    info: 'GET /admin/health HTTP/1.1 | Authorization: Basic [REDACTED]',
    capturePhase: 'baseline',
    cleartextAlert: true,
    decodedSummary:
      'Requête HTTP en clair sur le port 80 contenant un en-tête Basic Authorization encodé en Base64 sans chiffrement TLS ni redirection HSTS.',
    redactionApplied: true,
  },
  {
    frameNumber: 67,
    timestamp: '00:00:19.405',
    sourceIp: '10.20.10.50',
    destIp: '10.20.20.18',
    protocol: 'RESP',
    length: 78,
    info: 'Redis Command: PING -> +PONG | INFO server -> 7.0.11',
    capturePhase: 'baseline',
    cleartextAlert: true,
    decodedSummary:
      'Requête inter-VLAN TCP/6379 depuis la sonde DMZ acceptée sans défi AUTH ni restriction ACL, renvoyant les métadonnées complètes du serveur Redis.',
    redactionApplied: false,
  },
  {
    frameNumber: 102,
    timestamp: '00:00:28.912',
    sourceIp: '10.20.20.14',
    destIp: '10.20.30.15',
    protocol: 'SMB',
    length: 142,
    info: 'Negotiate Protocol Request -> Dialect: NT LM 0.12 (SMBv1)',
    capturePhase: 'baseline',
    cleartextAlert: true,
    decodedSummary:
      'Dialecte SMBv1 négocié entre VLAN 20 et VLAN 30 sans exigence de signature SMB, exposant le serveur d’archives aux relais NTLM et vulnérabilités héritées.',
    redactionApplied: false,
  },
  {
    frameNumber: 12,
    timestamp: '00:00:02.310',
    sourceIp: '10.20.10.50',
    destIp: '10.20.10.10',
    protocol: 'TLSv1.3',
    length: 517,
    info: 'Client Hello -> Server Hello (TLS_AES_256_GCM_SHA384)',
    capturePhase: 'retest',
    cleartextAlert: false,
    decodedSummary:
      'TCP SYN sur port 80 rejeté par RST ; le port 443 négocie TLS 1.3 avec confidentialité persistante et en-tête HSTS max-age=31536000.',
    redactionApplied: false,
  },
  {
    frameNumber: 28,
    timestamp: '00:00:06.845',
    sourceIp: '10.20.10.50',
    destIp: '10.20.20.18',
    protocol: 'TCP',
    length: 60,
    info: '10.20.10.50 -> 10.20.20.18 [SYN] Seq=0 (Aucune réponse / Filtré par ACL)',
    capturePhase: 'retest',
    cleartextAlert: false,
    decodedSummary:
      'Paquet SYN vers TCP/6379 silencieusement abandonné par la règle de pare-feu entrante du VLAN 20 ; Redis lié à 127.0.0.1 avec requirepass actif.',
    redactionApplied: false,
  },
  {
    frameNumber: 41,
    timestamp: '00:00:10.004',
    sourceIp: '10.20.10.50',
    destIp: '10.20.30.11',
    protocol: 'ICMP',
    length: 88,
    info: 'Destination unreachable (Communication administratively filtered)',
    capturePhase: 'retest',
    cleartextAlert: false,
    decodedSummary:
      'Le pare-feu applique explicitement la règle de refus VLAN 10 -> VLAN 30 lorsque la sonde DMZ tente une connexion MySQL TCP/3306.',
    redactionApplied: false,
  },
];

function buildFinding(
  partial: Omit<Finding, 'cvssScore' | 'cvssVector' | 'severity'>,
): Finding {
  const { score, severity, vector } = calculateCvssV31(partial.cvssMetrics);
  return {
    ...partial,
    cvssScore: score,
    cvssVector: vector,
    severity,
  };
}

export const INITIAL_FINDINGS: Finding[] = [
  buildFinding({
    id: 'NET-01',
    title: 'Broker Redis sans authentification joignable entre VLAN',
    hostIp: '10.20.20.18',
    vlanName: 'VLAN 20 · Tier Applicatif',
    port: 6379,
    protocol: 'tcp',
    category: 'Exposed Service',
    cvssMetrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },
    status: 'Remediated',
    summary:
      'Redis 7.0.11 écoutait sur 0.0.0.0:6379 avec protected-mode désactivé et sans mot de passe requirepass, permettant à tout hôte du VLAN 10 ou VLAN 20 de lire ou modifier les jetons de session.',
    businessImpact:
      'En cas de compromission du reverse proxy DMZ, un attaquant peut extraire les sessions actives, altérer les files applicatives ou injecter des clés SSH via la persistance RDB.',
    reproducibleSteps: [
      'Depuis la sonde DMZ autorisée (10.20.10.50), exécuter : nmap -sV -p 6379 10.20.20.18',
      'Vérifier que le port 6379/tcp apparaît ouvert sans filtrage.',
      'Exécuter : redis-cli -h 10.20.20.18 PING && redis-cli -h 10.20.20.18 INFO server',
      'Observer la réponse +PONG et la configuration complète sans authentification.',
    ],
    evidenceRef: '2026-11-10_baseline/vlan20_capture.pcapng (Trame #67)',
    remediationSummary:
      'Liaison de Redis à 127.0.0.1, activation de requirepass + règles ACL, et règle UFW sur VLAN 20 bloquant TCP/6379 depuis le VLAN 10.',
    configBefore: `bind 0.0.0.0\nprotected-mode no\n# requirepass désactivé`,
    configAfter: `bind 127.0.0.1 10.20.20.18\nprotected-mode yes\nrequirepass <SECRET_64_CHARS_VAULT>\nrename-command FLUSHALL ""`,
    retestCommand: 'nmap -sS -Pn -p 6379 10.20.20.18',
    retestOutput: '6379/tcp filtered redis (aucune réponse depuis la sonde DMZ)',
    retestVerifiedDate: '2026-11-16',
  }),
  buildFinding({
    id: 'NET-02',
    title: 'Démon Telnet en clair actif sur le serveur applicatif',
    hostIp: '10.20.20.14',
    vlanName: 'VLAN 20 · Tier Applicatif',
    port: 23,
    protocol: 'tcp',
    category: 'Cleartext Traffic',
    cvssMetrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
    status: 'Remediated',
    summary:
      'Un service hérité inetd/telnetd était resté actif sur TCP/23 d’app-api-01, transmettant les identifiants d’administration et les sessions shell en texte clair.',
    businessImpact:
      'Une écoute passive sur n’importe quel segment ponté révèle les mots de passe opérateurs en clair, menant à une prise de contrôle complète du serveur.',
    reproducibleSteps: [
      'Lancer l’énumération de service : nmap -sV -p 23 10.20.20.14',
      'Capturer le trafic dans Wireshark avec le filtre tcp.port == 23.',
      'Initier une connexion test et constater l’envoi d’octets ASCII non chiffrés.',
    ],
    evidenceRef: '2026-11-10_baseline/vlan20_capture.pcapng (Trame #14)',
    remediationSummary:
      'Arrêt et suppression du paquet telnetd/openbsd-inetd, fermeture de TCP/23 au pare-feu local et obligation d’utiliser SSH par clé depuis le bastion VLAN 99.',
    configBefore: `# /etc/inetd.conf\ntelnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd`,
    configAfter: `# systemctl disable --now inetd.service && apt purge -y telnetd\nufw deny 23/tcp`,
    retestCommand: 'nmap -sS -p 23 10.20.20.14',
    retestOutput: '23/tcp closed telnet (RST renvoyé ; unité inactive)',
    retestVerifiedDate: '2026-11-16',
  }),
  buildFinding({
    id: 'NET-03',
    title: 'Chemin latéral inter-VLAN de la DMZ vers Base & SMB',
    hostIp: '10.20.30.11',
    vlanName: 'VLAN 30 · Données & Stockage',
    port: 3306,
    protocol: 'tcp',
    category: 'Segmentation Gap',
    cvssMetrics: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'L', A: 'N' },
    status: 'Remediated',
    summary:
      'La politique de routage autorisait une communication L3 directe du VLAN 10 (DMZ) vers le VLAN 30 (Données), exposant MySQL TCP/3306 et SMB TCP/445 sans isolation de tiers.',
    businessImpact:
      'Enfreint la défense en profondeur : une seule faille web en DMZ donne un accès réseau direct aux bases de données et partages de fichiers internes.',
    reproducibleSteps: [
      'Depuis la DMZ (10.20.10.50), exécuter : nmap -Pn -p 3306,445 10.20.30.0/24',
      'Observer 3306/tcp ouvert sur 10.20.30.11 et 445/tcp ouvert sur 10.20.30.15.',
    ],
    evidenceRef: '2026-11-10_baseline/nmap_full.txt',
    remediationSummary:
      'Déploiement d’une ACL nftables avec état bloquant tout trafic VLAN 10 -> VLAN 30 et limitant MySQL TCP/3306 à la seule IP source 10.20.20.14.',
    configBefore: `ip saddr 10.20.10.0/24 ip daddr 10.20.30.0/24 accept`,
    configAfter: `ip saddr 10.20.10.0/24 ip daddr 10.20.30.0/24 log prefix "ACL_DROP_DMZ_DATA " drop\nip saddr 10.20.20.14 ip daddr 10.20.30.11 tcp dport 3306 ct state new,established accept`,
    retestCommand: 'nmap -Pn -p 3306,445 10.20.30.11 10.20.30.15',
    retestOutput: '3306/tcp filtered mysql · 445/tcp filtered microsoft-ds (ICMP admin-prohibited journalisé)',
    retestVerifiedDate: '2026-11-16',
  }),
  buildFinding({
    id: 'NET-04',
    title: 'Protocole SMBv1 activé sans signature sur le serveur de fichiers',
    hostIp: '10.20.30.15',
    vlanName: 'VLAN 30 · Données & Stockage',
    port: 445,
    protocol: 'tcp',
    category: 'Weak Configuration',
    cvssMetrics: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'L' },
    status: 'Remediated',
    summary:
      'Le serveur de fichiers Windows du laboratoire négociait SMBv1 (NT LM 0.12) sans imposer la signature des paquets SMB, l’exposant au relais NTLM et aux vecteurs historiques.',
    businessImpact:
      'Permet l’usurpation par relais d’authentification et l’énumération de partages depuis un hôte compromis du VLAN 20.',
    reproducibleSteps: [
      'Exécuter le script NSE : nmap -p 445 --script smb-protocols,smb2-security-mode 10.20.30.15',
      'Vérifier dans Wireshark la réponse Negotiate Protocol confirmant le dialecte SMBv1.',
    ],
    evidenceRef: '2026-11-10_baseline/vlan20_capture.pcapng (Trame #102)',
    remediationSummary:
      'Désactivation de SMBv1, activation obligatoire de RequireSecuritySignature=1 (signature SMBv3) et restriction du port 445 au sous-réseau d’administration.',
    configBefore: `Set-SmbServerConfiguration -EnableSMB1Protocol $true -RequireSecuritySignature $false`,
    configAfter: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force`,
    retestCommand: 'nmap -p 445 --script smb-protocols 10.20.30.15 (depuis VLAN 99)',
    retestOutput: 'SMBv1 désactivé ; SMB 3.1.1 négocié avec signature obligatoire',
    retestVerifiedDate: '2026-11-16',
  }),
  buildFinding({
    id: 'NET-05',
    title: 'Interface admin HTTP en clair et absence de HSTS sur la passerelle',
    hostIp: '10.20.10.10',
    vlanName: 'VLAN 10 · Zone DMZ',
    port: 80,
    protocol: 'tcp',
    category: 'Cleartext Traffic',
    cvssMetrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
    status: 'Remediated',
    summary:
      'La passerelle Nginx servait /admin/health sur le port HTTP 80 non chiffré en acceptant l’authentification Basic sans redirection HTTPS.',
    businessImpact:
      'Expose les identifiants Basic Auth (Base64) et jetons d’accès à toute interception réseau dans le domaine de diffusion DMZ.',
    reproducibleSteps: [
      'Exécuter : curl -i http://10.20.10.10/admin/health',
      'Constater une réponse directe sans redirection 301 HTTPS ni en-tête Strict-Transport-Security.',
    ],
    evidenceRef: '2026-11-10_baseline/vlan20_capture.pcapng (Trame #39)',
    remediationSummary:
      'Fermeture de l’écoute HTTP en clair, restriction de /admin/* au bastion VLAN 99 et activation exclusive de TLS 1.3 + HSTS.',
    configBefore: `listen 80;\nlocation /admin/ { auth_basic "Lab"; }`,
    configAfter: `listen 443 ssl http2;\nssl_protocols TLSv1.3;\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
    retestCommand: 'nmap -sV -p 80,443 10.20.10.10',
    retestOutput: '80/tcp closed http · 443/tcp open ssl/http (TLSv1.3)',
    retestVerifiedDate: '2026-11-16',
  }),
  buildFinding({
    id: 'NET-06',
    title: 'Authentification SSH par mot de passe encore active en interne',
    hostIp: '10.20.10.10',
    vlanName: 'VLAN 10 · Zone DMZ',
    port: 22,
    protocol: 'tcp',
    category: 'Weak Configuration',
    cvssMetrics: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
    status: 'Open',
    summary:
      'Bien que l’entrée SSH DMZ ait été filtrée par pare-feu, le fichier local sshd_config d’edge-gw-01 autorise toujours PasswordAuthentication yes depuis les pairs internes.',
    businessImpact:
      'Un pivot interne depuis un pair compromis pourrait encore tenter une attaque par force brute sur le mot de passe SSH d’edge-gw-01.',
    reproducibleSteps: [
      'Inspecter les méthodes SSH : ssh -o PreferredAuthentications=none 10.20.10.10 (depuis VLAN 99)',
      'Observer la présence de « publickey,password » dans les méthodes acceptées.',
    ],
    evidenceRef: '2026-11-16_retest/sshd_audit.txt',
    remediationSummary:
      'Configurer PasswordAuthentication no et PermitRootLogin no dans /etc/ssh/sshd_config puis recharger sshd lors de la prochaine fenêtre de maintenance.',
    configBefore: `PasswordAuthentication yes\nPermitRootLogin prohibit-password`,
    configAfter: `PasswordAuthentication no\nPermitRootLogin no\nAllowUsers netops@10.20.99.5`,
    retestCommand: 'sshd -T | grep -E "passwordauthentication|permitrootlogin"',
    retestOutput: 'En attente de fenêtre de maintenance sur edge-gw-01 pour rechargement sshd.',
    retestVerifiedDate: null,
  }),
];

export const EVIDENCE_ARTIFACTS: EvidenceArtifact[] = [
  {
    id: 'EV-01',
    folder: '2026-11-10_baseline',
    filename: 'nmap_full.txt',
    artifactType: 'Nmap Scan',
    sha256: '8a4f92c1e70d3b54920f8431b6e27c1093a4d118c77f02e89c45210a3f91b220',
    redacted: false,
    command: 'nmap -sS -sV -O -p 21,22,23,80,139,443,445,3306,6379,8080,8443 -oN nmap_full.txt 10.20.0.0/16',
    previewExcerpt:
      '6 hôtes actifs découverts sur 10.20.0.0/16 ; 12 ports TCP ouverts incluant Telnet (23), Redis (6379), SMB (445) et MySQL (3306).',
  },
  {
    id: 'EV-02',
    folder: '2026-11-10_baseline',
    filename: 'vlan20_capture.pcapng',
    artifactType: 'Wireshark PCAP',
    sha256: '3d91b74a22c08e5f91c2b84a10293e8f6b12c4d9e8a7f01324567890abcdef12',
    redacted: true,
    command: 'tshark -i eth1 -f "net 10.20.0.0/16" -w vlan20_capture.pcapng -a duration:60',
    previewExcerpt:
      '142 trames capturées. Détection d’une connexion Telnet en clair (Trame #14), HTTP Basic Auth (Trame #39), PING Redis sans auth (Trame #67) et dialecte SMBv1 (Trame #102). Secrets masqués.',
  },
  {
    id: 'EV-03',
    folder: '2026-11-14_remediation',
    filename: 'nftables_segmentation.conf',
    artifactType: 'Firewall Ruleset',
    sha256: '5c22e801d4f7b3a9c6e1209876543210fedcba9876543210abcdef0123456789',
    redacted: false,
    command: 'sudo nft -f /etc/nftables.d/vlan_segmentation.conf && sudo nft list ruleset',
    previewExcerpt:
      'Application d’une politique inter-VLAN de refus par défaut entre VLAN 10 (DMZ), VLAN 20 (App), VLAN 30 (Données) et VLAN 99 (Admin) avec exceptions explicites.',
  },
  {
    id: 'EV-04',
    folder: '2026-11-14_remediation',
    filename: 'service_hardening_diffs.patch',
    artifactType: 'Config Diff',
    sha256: '9f01a4b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e',
    redacted: true,
    command: 'git diff --no-index baseline_configs/ hardened_configs/ > service_hardening_diffs.patch',
    previewExcerpt:
      'Correctif unifié désactivant telnetd, liant Redis à 127.0.0.1 avec secret Vault, désactivant SMBv1 et imposant TLS 1.3 sur Nginx.',
  },
  {
    id: 'EV-05',
    folder: '2026-11-16_retest',
    filename: 'nmap_retest.txt',
    artifactType: 'Retest Log',
    sha256: 'e71234abcd5678ef901234567890abcdef11223344556677889900aabbccdd11',
    redacted: false,
    command: 'nmap -sS -sV -p 21,22,23,80,139,443,445,3306,6379,8080,8443 -oN nmap_retest.txt 10.20.0.0/16',
    previewExcerpt:
      'Le contre-audit depuis la sonde DMZ confirme une réduction de 75 % des ports exposés (12 -> 3). Telnet, HTTP, Redis, MySQL et SMB ne sont plus joignables depuis la DMZ.',
  },
];

export const LIMITATIONS_AND_ROADMAP: LimitationItem[] = [
  {
    id: 'LIM-01',
    area: 'Pont virtuel vs. Trunk 802.1Q physique',
    limitation:
      'La segmentation du laboratoire repose sur des espaces réseau Linux et nftables ; les mécanismes matériels de niveau 2 (DAI, DHCP snooping, saut de VLAN) n’ont pas été testés physiquement.',
    mitigationOrNextStep:
      'Déployer les règles sur un commutateur L3 administrable ou une maquette GNS3/EVE-NG avant la mise en production.',
    scaleHorizon: 'Immediate',
  },
  {
    id: 'LIM-02',
    area: 'Périmètre boîte noire sans agent',
    limitation:
      'L’audit portait sur l’exposition réseau inter-VLAN et les protocoles en transit, et non sur l’audit authentifié des benchmarks CIS système ou le SAST applicatif.',
    mitigationOrNextStep:
      'Compléter les scans réseau par des contrôles de conformité authentifiés Ansible/OpenSCAP sur les VLAN 20 et 30.',
    scaleHorizon: '30-Day',
  },
  {
    id: 'LIM-03',
    area: 'Comparaison manuelle à l’échelle 10x',
    limitation:
      'L’inspection manuelle Nmap + Wireshark reste adaptée à 6 hôtes et 4 VLAN, mais devient insuffisante au-delà de 60 hôtes ou avec des conteneurs éphémères.',
    mitigationOrNextStep:
      'Automatiser des pipelines nocturnes Nmap XML diff remontant toute dérive de port ouvert vers le SIEM.',
    scaleHorizon: '10x Production Scale',
  },
];

export const VIVA_QUESTIONS: VivaQuestion[] = [
  {
    id: 'VQ-1',
    question: 'Quel problème métier ce projet résout-il et comment le succès a-t-il été défini ?',
    answer:
      'Il fournit aux responsables Infrastructure et SecOps un jalon de validation reproductible avant la bascule d’un réseau segmenté en production. Le succès a été défini dès le départ : zéro chemin latéral non autorisé DMZ vers Données, zéro protocole d’administration en clair et preuve par contre-audit avant/après.',
  },
  {
    id: 'VQ-2',
    question: 'Quelle décision technique ou d’architecture a eu le plus grand impact sur le résultat ?',
    answer:
      'L’application stricte de garde-fous CIDR (10.20.0.0/16) couplée à un moteur déterministe de comparaison Nmap avant/après. Séparer les preuves brutes du calcul CVSS garantit que chaque correctif soit auditable indépendamment.',
  },
  {
    id: 'VQ-3',
    question: 'Comment avez-vous validé la qualité et l’exactitude de vos résultats ?',
    answer:
      'Chaque constat est corrélé à une sonde Nmap et à une trame Wireshark capturée. Après durcissement nftables et applicatif, nous avons relancé exactement les mêmes scans depuis la sonde DMZ (10.20.10.50) et testé unitairement le parseur ainsi que le calculateur CVSS.',
  },
  {
    id: 'VQ-4',
    question: 'Quels cas limites, risques ou limitations avez-vous identifiés ?',
    answer:
      'Nous gérons explicitement le blocage des IP publiques hors périmètre, la distinction entre ports filtrés et fermés, les entrées malformées et le masquage des secrets dans les PCAP. Limite majeure : un laboratoire virtuel ne valide pas la sécurité L2 des commutateurs physiques.',
  },
  {
    id: 'VQ-5',
    question: 'Que faudrait-il adapter pour supporter 10× plus d’hôtes ou de sous-réseaux ?',
    answer:
      'Remplacer les scans ponctuels par des sondes Nmap XML distribuées par VLAN alimentant un inventaire PostgreSQL, déclencher des alertes SIEM automatiques sur dérive de ports et gérer les ACL en Infrastructure-as-Code (Terraform/Ansible).',
  },
  {
    id: 'VQ-6',
    question: 'Comment expliquer ce projet à un interlocuteur non technique ?',
    answer:
      'Imaginez notre réseau comme un immeuble de bureaux : au départ, un visiteur dans le hall (DMZ) pouvait accéder directement au coffre-fort (VLAN Données) et lire du courrier non scellé (Telnet/HTTP). Nous avons verrouillé les portes entre services, chiffré les échanges et retesté chaque serrure.',
  },
  {
    id: 'VQ-7',
    question: 'Quelle partie du projet a demandé le plus de résolution de problème autonome ?',
    answer:
      'Comprendre pourquoi MySQL (3306) restait joignable depuis la DMZ malgré la configuration locale, en remontant la cause jusqu’aux règles de routage inter-VLAN trop permissives et en prouvant via les réponses ICMP admin-prohibited dans Wireshark que la nouvelle politique nftables bloquait bien le trafic.',
  },
];
