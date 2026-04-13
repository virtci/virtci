import { useState } from 'react';
import './App.css';

// ── Types ──────────────────────────────────────────────────────

type Page = 'home' | 'dashboard' | 'pricing';
type DashTab = 'vms' | 'billing' | 'audit';
type Mode = 'cloud' | 'self_hosted';

interface Org {
  id: string;
  name: string;
  role: 'owner' | 'member' | 'read';
  personal?: boolean;
}

const PERSONAL_ORG: Org = { id: 'personal', name: 'personal', role: 'owner', personal: true };

interface OrgData {
  plan: string;
  planPrice: string;
  storageUsedGB: number;
  storageLimitGB: number;
  renewsOn: string;
}

interface VM {
  id: string;
  name: string;
  description: string;
  arch: 'x86_64' | 'arm64' | 'riscv64';
  os: string;
  tags: string[];
  visibility: 'public' | 'private';
  namespace: string;
  disk: string;
  minSpec: { cpu: string; ram: string; disk: string };
}

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  resource: string;
}

interface Comment {
  id: string;
  author: string;
  time: string;
  text: string;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ORGS: Org[] = [
  { id: 'o1', name: 'acme-org', role: 'owner' },
  { id: 'o2', name: 'gabe-labs', role: 'member' },
  { id: 'o3', name: 'oss-collective', role: 'read' },
];

const MOCK_ORG_DATA: Record<string, OrgData> = {
  'acme-org': {
    plan: 'Pro',
    planPrice: '$29',
    storageUsedGB: 255,
    storageLimitGB: 400,
    renewsOn: 'May 11, 2026',
  },
  'gabe-labs': {
    plan: 'Starter',
    planPrice: '$5',
    storageUsedGB: 12,
    storageLimitGB: 20,
    renewsOn: 'Jun 3, 2026',
  },
  'oss-collective': {
    plan: 'Team',
    planPrice: '$79',
    storageUsedGB: 1100,
    storageLimitGB: 2048,
    renewsOn: 'Apr 30, 2026',
  },
  personal: {
    plan: 'Pro',
    planPrice: '$29',
    storageUsedGB: 78,
    storageLimitGB: 400,
    renewsOn: 'May 11, 2026',
  },
};

const MOCK_ORG_AUDIT: Record<string, AuditEntry[]> = {
  personal: [
    {
      id: 'p1',
      timestamp: '2026-04-11 10:00',
      action: 'VM created',
      resource: 'my-dev-box',
      actor: 'you',
    },
    {
      id: 'p2',
      timestamp: '2026-04-10 14:20',
      action: 'Visibility → private',
      resource: 'my-rust-sandbox',
      actor: 'you',
    },
  ],
  'acme-org': [
    {
      id: 'a1',
      timestamp: '2026-04-11 14:32',
      action: 'Downloaded image',
      resource: 'ubuntu-dev-node',
      actor: 'you',
    },
    {
      id: 'a2',
      timestamp: '2026-04-11 12:08',
      action: 'Visibility → private',
      resource: 'arm-python-ml',
      actor: 'you',
    },
    {
      id: 'a3',
      timestamp: '2026-04-09 17:15',
      action: 'Image accessed',
      resource: 'go-backend',
      actor: 'ci-bot',
    },
    {
      id: 'a4',
      timestamp: '2026-04-09 11:03',
      action: 'VM created',
      resource: 'riscv-embedded',
      actor: 'you',
    },
  ],
  'gabe-labs': [
    {
      id: 'b1',
      timestamp: '2026-04-10 09:20',
      action: 'VM created',
      resource: 'rust-toolchain',
      actor: 'gabe',
    },
    {
      id: 'b2',
      timestamp: '2026-04-08 16:44',
      action: 'Downloaded image',
      resource: 'rust-toolchain',
      actor: 'you',
    },
  ],
  'oss-collective': [
    {
      id: 'c1',
      timestamp: '2026-04-11 10:05',
      action: 'Image accessed',
      resource: 'k8s-playground',
      actor: 'dana',
    },
    {
      id: 'c2',
      timestamp: '2026-04-10 14:30',
      action: 'Downloaded image',
      resource: 'k8s-playground',
      actor: 'you',
    },
    {
      id: 'c3',
      timestamp: '2026-04-07 08:12',
      action: 'VM made public',
      resource: 'k8s-playground',
      actor: 'dana',
    },
  ],
};

const MOCK_PERSONAL_VMS: VM[] = [
  {
    id: 'p1',
    name: 'my-dev-box',
    description: 'Personal ARM dev environment with Neovim, tmux, and dotfiles.',
    arch: 'arm64',
    os: 'Ubuntu 24.04',
    tags: ['personal'],
    visibility: 'private',
    namespace: 'personal',
    disk: '40 GB',
    minSpec: { cpu: '2 vCPU', ram: '4 GB', disk: '20 GB' },
  },
  {
    id: 'p2',
    name: 'my-rust-sandbox',
    description: 'Rust nightly sandbox for personal experimentation.',
    arch: 'x86_64',
    os: 'Debian 12',
    tags: ['rust'],
    visibility: 'private',
    namespace: 'personal',
    disk: '20 GB',
    minSpec: { cpu: '1 vCPU', ram: '2 GB', disk: '10 GB' },
  },
  {
    id: 'p3',
    name: 'my-public-demo',
    description: 'Public demo environment shared for open-source contributions.',
    arch: 'x86_64',
    os: 'Ubuntu 22.04',
    tags: ['demo'],
    visibility: 'public',
    namespace: 'personal',
    disk: '15 GB',
    minSpec: { cpu: '1 vCPU', ram: '1 GB', disk: '8 GB' },
  },
];

const MOCK_VMS: VM[] = [
  {
    id: '1',
    name: 'ubuntu-dev-node',
    description: 'Node.js 20 dev environment with pnpm and git pre-configured.',
    arch: 'x86_64',
    os: 'Ubuntu 24.04',
    tags: ['nodejs', 'javascript'],
    visibility: 'public',
    namespace: 'acme-org',
    disk: '40 GB',
    minSpec: { cpu: '2 vCPU', ram: '4 GB', disk: '20 GB' },
  },
  {
    id: '2',
    name: 'arm-python-ml',
    description: 'Python 3.12 with PyTorch and CUDA bindings for ARM.',
    arch: 'arm64',
    os: 'Debian 12',
    tags: ['python', 'ml'],
    visibility: 'private',
    namespace: 'acme-org',
    disk: '80 GB',
    minSpec: { cpu: '4 vCPU', ram: '16 GB', disk: '40 GB' },
  },
  {
    id: '3',
    name: 'go-backend',
    description: 'Minimal Alpine image with Go 1.23 toolchain.',
    arch: 'x86_64',
    os: 'Alpine 3.19',
    tags: ['golang', 'backend'],
    visibility: 'public',
    namespace: 'acme-org',
    disk: '20 GB',
    minSpec: { cpu: '1 vCPU', ram: '512 MB', disk: '10 GB' },
  },
  {
    id: '4',
    name: 'riscv-embedded',
    description: 'Experimental RISC-V 64 image for embedded targets.',
    arch: 'riscv64',
    os: 'Fedora 39',
    tags: ['embedded'],
    visibility: 'private',
    namespace: 'acme-org',
    disk: '10 GB',
    minSpec: { cpu: '1 vCPU', ram: '1 GB', disk: '8 GB' },
  },
  {
    id: '5',
    name: 'rust-toolchain',
    description: 'Rust stable + nightly with cross-compilation support.',
    arch: 'x86_64',
    os: 'Ubuntu 22.04',
    tags: ['rust', 'systems'],
    visibility: 'public',
    namespace: 'gabe-labs',
    disk: '30 GB',
    minSpec: { cpu: '2 vCPU', ram: '4 GB', disk: '15 GB' },
  },
  {
    id: '6',
    name: 'k8s-playground',
    description: 'Single-node k3s cluster with Helm and kubectl.',
    arch: 'arm64',
    os: 'Ubuntu 24.04',
    tags: ['kubernetes', 'docker'],
    visibility: 'public',
    namespace: 'oss-collective',
    disk: '100 GB',
    minSpec: { cpu: '4 vCPU', ram: '8 GB', disk: '50 GB' },
  },
  {
    id: '7',
    name: 'win11-dev',
    description: 'Windows 11 Pro with VS Code, Git, WSL2, and .NET 8 SDK pre-installed.',
    arch: 'x86_64',
    os: 'Windows 11',
    tags: ['windows', 'dotnet'],
    visibility: 'public',
    namespace: 'acme-org',
    disk: '80 GB',
    minSpec: { cpu: '4 vCPU', ram: '8 GB', disk: '40 GB' },
  },
  {
    id: '8',
    name: 'win10-ltsc',
    description: 'Windows 10 LTSC for legacy enterprise and compatibility testing.',
    arch: 'x86_64',
    os: 'Windows 10',
    tags: ['windows', 'legacy'],
    visibility: 'public',
    namespace: 'gabe-labs',
    disk: '60 GB',
    minSpec: { cpu: '2 vCPU', ram: '4 GB', disk: '30 GB' },
  },
  {
    id: '9',
    name: 'macos-sequoia',
    description: 'macOS 15 Sequoia for iOS and macOS development with Xcode 16.',
    arch: 'arm64',
    os: 'macOS 15',
    tags: ['macos', 'xcode'],
    visibility: 'public',
    namespace: 'acme-org',
    disk: '120 GB',
    minSpec: { cpu: '4 vCPU', ram: '8 GB', disk: '60 GB' },
  },
  {
    id: '10',
    name: 'macos-tahoe',
    description: 'macOS 26 Tahoe early-access image for Swift and CI pipelines.',
    arch: 'arm64',
    os: 'macOS 26',
    tags: ['macos', 'swift', 'ci'],
    visibility: 'public',
    namespace: 'oss-collective',
    disk: '130 GB',
    minSpec: { cpu: '4 vCPU', ram: '8 GB', disk: '65 GB' },
  },
  {
    id: '11',
    name: 'freebsd-base',
    description: 'FreeBSD 14.1 minimal base system for networking and BSD workloads.',
    arch: 'x86_64',
    os: 'FreeBSD 14',
    tags: ['bsd', 'networking'],
    visibility: 'public',
    namespace: 'oss-collective',
    disk: '20 GB',
    minSpec: { cpu: '1 vCPU', ram: '1 GB', disk: '10 GB' },
  },
];

// const MOCK_AUDIT: AuditEntry[] = [
//   { id:'a1', timestamp:'2026-04-11 14:32', action:'Downloaded image',     resource:'ubuntu-dev-node', actor:'you'    },
//   { id:'a2', timestamp:'2026-04-11 12:08', action:'Visibility → private', resource:'arm-python-ml',   actor:'you'    },
//   { id:'a3', timestamp:'2026-04-09 17:15', action:'Image accessed',       resource:'go-backend',      actor:'ci-bot' },
//   { id:'a4', timestamp:'2026-04-09 11:03', action:'VM created',           resource:'riscv-embedded',  actor:'you'    },
// ]

const MOCK_COMMENTS: Comment[] = [
  {
    id: 'c1',
    author: 'gabe',
    time: '2h ago',
    text: 'Works great on M2 Mac. Had to adjust the network MTU but otherwise smooth.',
  },
  {
    id: 'c2',
    author: 'alex',
    time: '1d ago',
    text: 'Does this support cloud-init? Trying to pass user-data on first boot.',
  },
  {
    id: 'c3',
    author: 'you',
    time: '1d ago',
    text: 'Yes — cloud-init is included. Pass --user-data when pulling the image.',
  },
];

const SIDEBAR_CATEGORIES = [
  {
    label: 'Languages',
    items: [
      { abbr: 'JS', label: 'JavaScript / Node' },
      { abbr: 'PY', label: 'Python' },
      { abbr: 'GO', label: 'Go' },
      { abbr: 'RS', label: 'Rust' },
      { abbr: 'JVM', label: 'Java / JVM' },
      { abbr: 'RB', label: 'Ruby' },
    ],
  },
  {
    label: 'Frameworks',
    items: [
      { abbr: 'RCT', label: 'React / Next.js' },
      { abbr: 'DKR', label: 'Docker' },
      { abbr: 'K8S', label: 'Kubernetes' },
      { abbr: 'ML', label: 'PyTorch / ML' },
      { abbr: 'WA', label: 'WASM / Edge' },
    ],
  },
];

// ── OS family detection ────────────────────────────────────────
// Add patterns here to extend color-coding for new OS families.

type OsFamily = 'windows' | 'linux' | 'macos' | 'other';

function getOsFamily(os: string): OsFamily {
  const l = os.toLowerCase();
  if (l.includes('windows')) return 'windows';
  if (l.includes('macos') || l.includes('darwin')) return 'macos';
  if (
    l.includes('ubuntu') ||
    l.includes('debian') ||
    l.includes('alpine') ||
    l.includes('fedora') ||
    l.includes('centos') ||
    l.includes('arch') ||
    l.includes('linux')
  )
    return 'linux';
  return 'other'; // FreeBSD, OpenBSD, Haiku, etc.
}

// ── Shared ─────────────────────────────────────────────────────

function Badge({
  children,
  variant,
}: {
  children: React.ReactNode;
  variant: 'arch' | 'public' | 'private' | 'tag';
}) {
  return <span className={`badge badge-${variant}`}>{children}</span>;
}

function OsBadge({ os }: { os: string }) {
  return <span className={`badge badge-os-${getOsFamily(os)}`}>{os}</span>;
}

function VisBadge({ v }: { v: VM['visibility'] }) {
  return <Badge variant={v}>{v === 'public' ? 'Public' : 'Private'}</Badge>;
}

// ── VM Card ────────────────────────────────────────────────────

function VMCard({ vm, onClick }: { vm: VM; onClick: () => void }) {
  const isPersonal = vm.namespace === 'personal';
  return (
    <div className={`vm-card vm-arch-${vm.arch}`} onClick={onClick}>
      <div className="vm-card-top">
        <div>
          <div className="vm-name">{vm.name}</div>
          <div className="vm-desc">{vm.description}</div>
        </div>
        {isPersonal && <VisBadge v={vm.visibility} />}
      </div>
      <div className="vm-badges">
        <OsBadge os={vm.os} />
        <Badge variant="arch">{vm.arch}</Badge>
        <span className="badge badge-disk">{vm.disk}</span>
        {vm.tags.map((t) => (
          <Badge key={t} variant="tag">
            {t}
          </Badge>
        ))}
      </div>
      <div className="vm-footer">
        <span className="vm-meta">
          <span className="vm-disk-size">{vm.disk}</span>
          <span style={{ color: 'var(--border)', userSelect: 'none' }}>·</span>
          <span style={{ color: 'var(--text-muted)' }}>{vm.namespace}</span>
        </span>
        <button className="vm-download-btn" title="Download" onClick={(e) => e.stopPropagation()}>
          <i className="fi fi-rr-download" />
        </button>
      </div>
    </div>
  );
}

// ── VM Detail Modal ────────────────────────────────────────────

function VMModal({ vm, onClose }: { vm: VM; onClose: () => void }) {
  const [comment, setComment] = useState('');

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>
          ✕
        </button>

        <div className="modal-title">{vm.name}</div>
        <div className="modal-sub">
          {vm.namespace}/{vm.name}
        </div>

        <div className="row mb-10" style={{ flexWrap: 'wrap' }}>
          <OsBadge os={vm.os} />
          <Badge variant="arch">{vm.arch}</Badge>
          <span className="badge badge-disk">{vm.disk}</span>
          {vm.namespace === 'personal' && <VisBadge v={vm.visibility} />}
          {vm.tags.map((t) => (
            <Badge key={t} variant="tag">
              {t}
            </Badge>
          ))}
        </div>

        <p
          style={{
            fontSize: 'var(--fs-sm)',
            color: 'var(--text-secondary)',
            lineHeight: 1.55,
            marginBottom: 16,
          }}
        >
          {vm.description}
        </p>

        <div className="inset mb-10">
          <div className="section-label" style={{ marginBottom: 14 }}>
            Specs &amp; Size
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
            <div className="spec-block">
              <div className="spec-key">OS</div>
              <div className="spec-value" style={{ fontSize: 'var(--fs-ui)' }}>
                {vm.os}
              </div>
            </div>
            <div className="spec-block">
              <div className="spec-key">Architecture</div>
              <div className="spec-value highlight">{vm.arch}</div>
            </div>
            <div className="spec-block">
              <div className="spec-key">Image Size</div>
              <div className="spec-value highlight">{vm.disk}</div>
            </div>
            <div className="spec-block">
              <div className="spec-key">Min CPU</div>
              <div className="spec-value">{vm.minSpec.cpu}</div>
            </div>
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(2, 1fr)',
              gap: 14,
              marginTop: 14,
            }}
          >
            <div className="spec-block">
              <div className="spec-key">Min RAM</div>
              <div className="spec-value">{vm.minSpec.ram}</div>
            </div>
            <div className="spec-block">
              <div className="spec-key">Default Max Disk</div>
              <div className="spec-value">{vm.minSpec.disk}</div>
            </div>
          </div>
        </div>

        <div className="mt-16">
          <div className="section-label" style={{ marginBottom: 8 }}>
            Discussion
          </div>
          {MOCK_COMMENTS.map((c) => (
            <div key={c.id} className="comment">
              <div className="avatar-sm">{c.author[0].toUpperCase()}</div>
              <div className="comment-body">
                <div className="comment-meta">
                  <span className="comment-author">{c.author}</span>
                  <span className="comment-ts">{c.time}</span>
                </div>
                <div className="comment-text">{c.text}</div>
              </div>
            </div>
          ))}
          <div className="comment-input-row">
            <div className="avatar-sm">Y</div>
            <textarea
              className="comment-input"
              rows={2}
              placeholder="Leave a comment…"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
            />
            <button className="btn btn-primary btn-sm" style={{ alignSelf: 'flex-end' }}>
              Post
            </button>
          </div>
        </div>

        <div className="row mt-16">
          <button className="btn btn-primary">
            <i className="fi fi-rr-download" style={{ fontSize: 16 }} /> Download VM
          </button>
          <button className="btn btn-ghost">Report</button>
        </div>
      </div>
    </div>
  );
}

// ── Dashboard tabs ─────────────────────────────────────────────

function VMsTab({ vms }: { vms: VM[] }) {
  const [selected, setSelected] = useState<VM | null>(null);
  return (
    <>
      {vms.length === 0 ? (
        <div className="empty">No VMs in this namespace yet.</div>
      ) : (
        <div className="vm-grid">
          {vms.map((vm) => (
            <VMCard key={vm.id} vm={vm} onClick={() => setSelected(vm)} />
          ))}
        </div>
      )}
      {selected && <VMModal vm={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

// Cloud billing tab — tier-based, shows upgrade prompts
function BillingTab({ data }: { data: OrgData }) {
  const pct = Math.round((data.storageUsedGB / data.storageLimitGB) * 100);
  const atLimit = pct >= 100;
  const barCls = pct > 80 ? 'danger' : pct > 60 ? 'warn' : '';

  return (
    <>
      {atLimit && (
        <div className="limit-banner limit-banner-cloud">
          <div>
            <div style={{ fontWeight: 600, marginBottom: 2 }}>Storage limit reached</div>
            <div style={{ fontSize: 'var(--fs-sm)', color: 'var(--text-secondary)' }}>
              You've used 100% of your plan's storage. Upgrade to continue uploading.
            </div>
          </div>
          <button className="btn btn-primary btn-sm">Upgrade plan</button>
        </div>
      )}

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-card-label">Current plan</div>
          <div className="stat-value">
            {data.planPrice}
            <span>/mo</span>
          </div>
          <div className="stat-sub">
            {data.plan} · renews {data.renewsOn}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Storage used</div>
          <div className="stat-value">
            {data.storageUsedGB} <span>GB</span>
          </div>
          <div className="progress">
            <div className={`progress-fill ${barCls}`} style={{ width: `${pct}%` }} />
          </div>
          <div className="stat-sub">
            {pct}% of {data.storageLimitGB} GB tier limit
          </div>
        </div>
      </div>

      <div className="section-label mb-10">Plans</div>
      <div className="plan-grid">
        {[
          {
            name: 'Free',
            price: '$0',
            sub: null,
            features: ['Unlimited public VM pulls', 'Join organizations', 'Community support'],
            current: false,
          },
          {
            name: 'Pro',
            price: '$5',
            sub: '+ $0.75 / 10 GB added',
            features: [
              '50 GB VM storage included',
              'Private VMs',
              'Audit log',
              'Email support',
              'Priority support',
            ],
            current: true,
          },
          {
            name: 'Enterprise',
            price: 'Custom',
            sub: 'per month',
            features: [
              'Custom deletion retention',
              'VM history + revert',
              'VM versioning',
              'Priority support',
              'Custom contracts',
            ],
            current: false,
          },
        ].map((p) => (
          <div key={p.name} className={`plan-card ${p.current ? 'current' : ''}`}>
            <div className="plan-name">
              {p.name}
              {p.current && <Badge variant="arch">current</Badge>}
            </div>
            <div className="plan-price">
              {p.price}
              <span>/mo</span>
            </div>
            {p.sub && (
              <div
                style={{
                  fontSize: 'var(--fs-label)',
                  color: 'var(--text-muted)',
                  marginBottom: 14,
                  marginTop: -10,
                }}
              >
                {p.sub}
              </div>
            )}
            <ul className="plan-features">
              {p.features.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            {!p.current && (
              <button className="btn btn-ghost btn-sm mt-10" style={{ width: '100%' }}>
                {p.price === 'Custom' ? 'Contact us' : 'Select'}
              </button>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

// Self-hosted storage tab — shows aggregate usage only; node management is external
function StorageTab() {
  return (
    <div className="stat-grid">
      <div className="stat-card">
        <div className="stat-card-label">Total used</div>
        <div className="stat-value">
          288 <span>GB used</span>
        </div>
        <div className="stat-sub">of 1.2 TB allocated</div>
      </div>
      <div className="stat-card">
        <div className="stat-card-label">Available</div>
        <div className="stat-value">
          912 <span>GB free</span>
        </div>
        <div className="progress">
          <div className="progress-fill" style={{ width: '24%' }} />
        </div>
        <div className="stat-sub">24% utilization</div>
      </div>
    </div>
  );
}

function AuditTab({ orgName }: { orgName: string }) {
  const entries = MOCK_ORG_AUDIT[orgName] ?? [];
  return (
    <>
      <div style={{ fontSize: 'var(--fs-sm)', color: 'var(--text-muted)', marginBottom: 16 }}>
        All actions within your namespace are recorded here.
      </div>
      {entries.length === 0 ? (
        <div className="empty">No activity recorded for this namespace.</div>
      ) : (
        entries.map((e) => (
          <div key={e.id} className="audit-row">
            <span className="audit-ts">{e.timestamp}</span>
            <span className="audit-action">
              {e.action} — <span className="audit-resource">{e.resource}</span>
            </span>
            <span className="audit-actor">{e.actor}</span>
          </div>
        ))
      )}
    </>
  );
}

// ── Navbar ─────────────────────────────────────────────────────

function Navbar({
  setPage,
  loggedIn,
  setLoggedIn,
  search,
  setSearch,
}: {
  setPage: (p: Page) => void;
  loggedIn: boolean;
  setLoggedIn: (v: boolean) => void;
  search: string;
  setSearch: (v: string) => void;
}) {
  return (
    <nav className="navbar">
      <div className="navbar-logo" onClick={() => setPage('home')}>
        <div className="logo-mark">V</div>
        VirtCI
      </div>

      <div className="navbar-search">
        <span className="search-icon">
          <i className="fi fi-rr-search" />
        </span>
        <input
          type="text"
          placeholder="Search by name, architecture, OS…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="navbar-right">
        <button className="nav-link" onClick={() => setPage('pricing')}>
          Pricing
        </button>
        {loggedIn ? (
          <>
            <button className="nav-link" onClick={() => setPage('dashboard')}>
              Dashboard
            </button>
            <button className="notif-btn">
              <i className="fi fi-rr-bell" style={{ fontSize: 17, lineHeight: 1 }} />
              <span className="notif-dot" />
            </button>
            <div className="avatar" title="Log out" onClick={() => setLoggedIn(false)}>
              JD
            </div>
          </>
        ) : (
          <>
            <button className="btn btn-ghost btn-sm" onClick={() => setLoggedIn(true)}>
              Log in
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                setLoggedIn(true);
                setPage('dashboard');
              }}
            >
              Sign up
            </button>
          </>
        )}
      </div>
    </nav>
  );
}

// ── Sidebar ────────────────────────────────────────────────────

function Sidebar({
  page,
  setPage,
  activeCategory,
  setActiveCategory,
  loggedIn,
  dashTab,
  setDashTab,
  org,
  setOrg,
  mode,
}: {
  page: Page;
  setPage: (p: Page) => void;
  activeCategory: string;
  setActiveCategory: (v: string) => void;
  loggedIn: boolean;
  dashTab: DashTab;
  setDashTab: (t: DashTab) => void;
  org: Org;
  setOrg: (o: Org) => void;
  mode: Mode;
}) {
  const [orgOpen, setOrgOpen] = useState(false);

  const billingLabel = mode === 'self_hosted' ? 'Storage' : 'Billing';

  return (
    <aside className="sidebar">
      {loggedIn && (
        <>
          {/* Org switcher */}
          <div className="org-switcher" onClick={() => setOrgOpen((o) => !o)}>
            {org.personal ? (
              <div className="personal-avatar">
                <i className="fi fi-sr-user" style={{ fontSize: 12 }} />
              </div>
            ) : (
              <div className="org-avatar">{org.name[0].toUpperCase()}</div>
            )}
            <div className="org-info">
              <div className="org-name">{org.personal ? 'Personal' : org.name}</div>
              <div className="org-role">{org.personal ? 'your workspace' : org.role}</div>
            </div>
            <span className="org-caret">{orgOpen ? '▴' : '▾'}</span>
          </div>

          {orgOpen && (
            <div className="org-dropdown">
              {/* Personal workspace — always at top */}
              <div
                className={`org-dropdown-item personal-item ${org.id === 'personal' ? 'active' : ''}`}
                onClick={() => {
                  setOrg(PERSONAL_ORG);
                  setOrgOpen(false);
                }}
              >
                <div className="org-avatar-personal">
                  <i className="fi fi-sr-user" style={{ fontSize: 8, lineHeight: 1 }} />
                </div>
                <span style={{ flex: 1 }}>Personal</span>
                <span style={{ fontSize: 'var(--fs-label)', color: 'var(--text-muted)' }}>you</span>
                {org.id === 'personal' && <span className="check">✓</span>}
              </div>
              <div className="org-dropdown-divider" />
              {MOCK_ORGS.map((o) => (
                <div
                  key={o.id}
                  className={`org-dropdown-item ${o.id === org.id ? 'active' : ''}`}
                  onClick={() => {
                    setOrg(o);
                    setOrgOpen(false);
                  }}
                >
                  <div className="org-avatar" style={{ width: 18, height: 18, fontSize: 9 }}>
                    {o.name[0].toUpperCase()}
                  </div>
                  <span style={{ flex: 1 }}>{o.name}</span>
                  <span style={{ fontSize: 'var(--fs-label)', color: 'var(--text-muted)' }}>
                    {o.role}
                  </span>
                  {o.id === org.id && <span className="check">✓</span>}
                </div>
              ))}
              <div className="org-dropdown-divider" />
              <div className="org-dropdown-action">
                <span>+</span> Create org
              </div>
            </div>
          )}

          <div className="sb-divider" />

          {/* Workspace nav */}
          <div className="sb-section">
            <div className="sb-label">Workspace</div>
            {(
              [
                ['vms', 'fi fi-rr-server', 'VMs'],
                ['billing', 'fi fi-rr-credit-card', billingLabel],
                ['audit', 'fi fi-rr-time-past', 'Audit Log'],
              ] as [DashTab, string, string][]
            ).map(([id, icon, label]) => (
              <div
                key={id}
                className={`sb-item ${page === 'dashboard' && dashTab === id ? 'active' : ''}`}
                data-tab={id}
                onClick={() => {
                  setPage('dashboard');
                  setDashTab(id);
                }}
              >
                <span className="sb-icon">
                  <i className={icon} />
                </span>
                {label}
              </div>
            ))}
          </div>

          <div className="sb-divider" />
        </>
      )}

      {/* Browse */}
      <div className="sb-section">
        <div className="sb-label">Browse</div>
        <div
          className={`sb-item ${page === 'home' && !activeCategory ? 'active' : ''}`}
          onClick={() => {
            setPage('home');
            setActiveCategory('');
          }}
        >
          <span className="sb-icon">
            <i className="fi fi-rr-apps" />
          </span>
          All VMs
        </div>
      </div>

      {SIDEBAR_CATEGORIES.map((cat) => (
        <div key={cat.label} className="sb-section">
          <div className="sb-label">{cat.label}</div>
          {cat.items.map((item) => (
            <div
              key={item.label}
              className={`sb-item ${activeCategory === item.label ? 'active' : ''}`}
              onClick={() => {
                setPage('home');
                setActiveCategory(item.label);
              }}
            >
              <span className="sb-icon">{item.abbr}</span>
              {item.label}
            </div>
          ))}
        </div>
      ))}
    </aside>
  );
}

// ── Pages ──────────────────────────────────────────────────────

function HomePage({ search, activeCategory }: { search: string; activeCategory: string }) {
  const [arch, setArch] = useState('All');
  const [selected, setSelected] = useState<VM | null>(null);

  const visible = MOCK_VMS.filter((vm) => {
    if (vm.visibility !== 'public') return false;
    if (arch !== 'All' && vm.arch !== arch) return false;
    if (search) {
      const q = search.toLowerCase();
      if (
        !vm.name.includes(q) &&
        !vm.os.toLowerCase().includes(q) &&
        !vm.arch.includes(q) &&
        !vm.tags.some((t) => t.includes(q))
      )
        return false;
    }
    if (activeCategory) {
      const q = activeCategory.split(' ')[0].toLowerCase();
      if (!vm.tags.some((t) => t.includes(q) || q.includes(t))) return false;
    }
    return true;
  });

  return (
    <div className="main">
      <div className="hero">
        <div className="hero-filters">
          {['All', 'x86_64', 'arm64', 'riscv64'].map((f) => (
            <button
              key={f}
              className={`chip ${arch === f ? 'active' : ''}`}
              onClick={() => setArch(f)}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="page" style={{ paddingTop: 0 }}>
        <div className="section-label">
          {activeCategory || 'Public VMs'} &nbsp;·&nbsp; {visible.length} results
        </div>
        {visible.length === 0 ? (
          <div className="empty">No public VMs match your search.</div>
        ) : (
          <div className="vm-grid mt-10">
            {visible.map((vm) => (
              <VMCard key={vm.id} vm={vm} onClick={() => setSelected(vm)} />
            ))}
          </div>
        )}
      </div>

      {selected && <VMModal vm={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function DashboardPage({
  tab,
  setTab,
  org,
  mode,
}: {
  tab: DashTab;
  setTab: (t: DashTab) => void;
  org: Org;
  mode: Mode;
}) {
  const isPersonal = org.personal === true;
  const canManage = org.role !== 'read';
  const vmsForOrg = isPersonal
    ? MOCK_PERSONAL_VMS
    : MOCK_VMS.filter((vm) => vm.namespace === org.name);
  const orgData = MOCK_ORG_DATA[org.name] ?? MOCK_ORG_DATA['acme-org'];
  const billingLabel = mode === 'self_hosted' ? 'Storage' : 'Billing';

  return (
    <div className="main">
      {mode === 'self_hosted' && (
        <div className="mode-banner">
          <div className="mode-banner-dot" />
          Self-hosted instance &nbsp;·&nbsp; Storage limits based on physical hardware
        </div>
      )}

      <div className="page">
        <div className="page-head">
          <div className="page-title">
            {tab === 'vms' && (isPersonal ? 'Personal VMs' : 'VMs')}
            {tab === 'billing' && billingLabel}
            {tab === 'audit' && 'Audit Log'}
          </div>
          <div className="page-sub">
            {isPersonal ? 'Your personal workspace' : `${org.name} · ${org.role}`}
            {tab === 'vms' && ` · ${vmsForOrg.length} VMs`}
          </div>
        </div>

        <div className="tabs">
          {(['vms', 'billing', 'audit'] as DashTab[])
            .filter((id) => {
              if (isPersonal && id === 'audit') return false;
              return canManage || id === 'vms' || id === 'billing';
            })
            .map((id) => (
              <button
                key={id}
                className={`tab ${tab === id ? 'active' : ''}`}
                onClick={() => setTab(id)}
              >
                {id === 'billing' ? billingLabel : id.charAt(0).toUpperCase() + id.slice(1)}
              </button>
            ))}
        </div>

        {tab === 'vms' && <VMsTab vms={vmsForOrg} />}
        {tab === 'billing' &&
          (mode === 'self_hosted' ? <StorageTab /> : <BillingTab data={orgData} />)}
        {tab === 'audit' && canManage && <AuditTab orgName={org.name} />}
      </div>
    </div>
  );
}

function PricingPage() {
  return (
    <div className="main">
      <div className="pricing-hero">
        <h2>Simple, transparent pricing</h2>
        <p>Start free. Scale as you grow. No hidden fees.</p>
      </div>
      <div className="page" style={{ paddingTop: 0 }}>
        <div className="plan-grid" style={{ maxWidth: 760, margin: '0 auto' }}>
          {[
            {
              name: 'Free',
              price: '$0',
              sub: null,
              features: ['Unlimited public VM pulls', 'Join organizations', 'Community support'],
            },
            {
              name: 'Pro',
              price: '$5',
              sub: '+ $0.75 / 10 GB added',
              features: [
                '50 GB VM storage included',
                'Private VMs',
                'Audit log',
                'Email support',
                'Priority support',
              ],
            },
            {
              name: 'Enterprise',
              price: 'Custom',
              sub: 'per month',
              features: [
                'Custom deletion retention',
                'VM history + revert',
                'VM versioning',
                'Priority support',
                'Custom contracts',
              ],
            },
          ].map((p) => (
            <div key={p.name} className="plan-card">
              <div className="plan-name">{p.name}</div>
              <div className="plan-price">
                {p.price}
                <span>/mo</span>
              </div>
              {p.sub && (
                <div
                  style={{
                    fontSize: 'var(--fs-label)',
                    color: 'var(--text-muted)',
                    marginBottom: 14,
                    marginTop: -10,
                  }}
                >
                  {p.sub}
                </div>
              )}
              <ul className="plan-features">
                {p.features.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              <button className="btn btn-primary mt-16" style={{ width: '100%' }}>
                {p.price === 'Custom' ? 'Contact us' : 'Get started'}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Root ───────────────────────────────────────────────────────

export default function App() {
  const [page, setPage] = useState<Page>('home');
  const [loggedIn, setLoggedIn] = useState(false);
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('');
  const [dashTab, setDashTab] = useState<DashTab>('vms');
  const [org, setOrg] = useState<Org>(MOCK_ORGS[0]);

  // Switch between 'cloud' and 'self_hosted' to see the difference
  const mode: Mode = 'self_hosted';

  const handleSetPage = (p: Page) => {
    if (p === 'home') setActiveCategory('');
    setPage(p);
  };

  const handleSwitchOrg = (o: Org) => {
    setOrg(o);
    setDashTab('vms'); // reset to VMs so you always land somewhere valid
    setPage('dashboard');
  };

  return (
    <div className="layout">
      <Navbar
        setPage={handleSetPage}
        loggedIn={loggedIn}
        setLoggedIn={setLoggedIn}
        search={search}
        setSearch={setSearch}
      />
      <Sidebar
        page={page}
        setPage={handleSetPage}
        activeCategory={activeCategory}
        setActiveCategory={setActiveCategory}
        loggedIn={loggedIn}
        dashTab={dashTab}
        setDashTab={setDashTab}
        org={org}
        setOrg={handleSwitchOrg}
        mode={mode}
      />

      {page === 'home' && <HomePage search={search} activeCategory={activeCategory} />}
      {page === 'dashboard' && loggedIn && (
        <DashboardPage tab={dashTab} setTab={setDashTab} org={org} mode={mode} />
      )}
      {page === 'dashboard' && !loggedIn && (
        <div className="main">
          <div className="empty" style={{ paddingTop: 120 }}>
            <div style={{ marginBottom: 16 }}>Sign in to view your dashboard</div>
            <button className="btn btn-primary" onClick={() => setLoggedIn(true)}>
              Log in
            </button>
          </div>
        </div>
      )}
      {page === 'pricing' && <PricingPage />}
    </div>
  );
}
