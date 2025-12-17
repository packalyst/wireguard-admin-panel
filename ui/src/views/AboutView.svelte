<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Tabs from '../components/Tabs.svelte'

  let { loading = $bindable(true) } = $props()

  let activeTab = $state('overview')
  let routerStatus = $state(null)

  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'info-circle' },
    { id: 'architecture', label: 'Architecture', icon: 'sitemap' },
    { id: 'api', label: 'API Reference', icon: 'code' },
    { id: 'services', label: 'Services', icon: 'server' }
  ]

  onMount(async () => {
    try {
      routerStatus = await apiGet('/api/vpn/router/status')
    } catch (e) {
      // Ignore
    }
    loading = false
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="info-circle"
    title="About"
    description="Unified admin panel for managing VPN infrastructure including WireGuard, Headscale, AdGuard DNS, and Traefik reverse proxy."
  />

  <div class="bg-card border border-border rounded-lg overflow-hidden">
    <Tabs {tabs} bind:activeTab urlKey="tab" />

    <div class="p-5">
      <!-- Overview Tab -->
      {#if activeTab === 'overview'}
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">What is this?</h3>
            <p class="text-sm text-muted-foreground leading-relaxed">
              This admin panel provides a unified interface for managing a complete VPN infrastructure stack. It integrates multiple services to provide secure, private network access with advanced features like DNS-level ad blocking, reverse proxy routing, and cross-network communication between different VPN types.
            </p>
          </div>

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Key Features</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <div class="flex items-center gap-2 mb-2">
                  <Icon name="users" size={18} class="text-primary" />
                  <span class="font-medium text-foreground">Headscale Management</span>
                </div>
                <p class="text-xs text-muted-foreground">Manage users, nodes, pre-auth keys, API keys, and routes for your Headscale/Tailscale network.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <div class="flex items-center gap-2 mb-2">
                  <Icon name="shield" size={18} class="text-success" />
                  <span class="font-medium text-foreground">WireGuard Peers</span>
                </div>
                <p class="text-xs text-muted-foreground">Create and manage WireGuard peers with QR codes for easy mobile setup.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <div class="flex items-center gap-2 mb-2">
                  <Icon name="shield-check" size={18} class="text-warning" />
                  <span class="font-medium text-foreground">AdGuard DNS</span>
                </div>
                <p class="text-xs text-muted-foreground">Network-wide ad blocking, safe browsing, parental controls, and DNS query logging.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <div class="flex items-center gap-2 mb-2">
                  <Icon name="lock" size={18} class="text-destructive" />
                  <span class="font-medium text-foreground">Firewall & Fail2Ban</span>
                </div>
                <p class="text-xs text-muted-foreground">Port management, IP blocking, intrusion detection with configurable jails.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <div class="flex items-center gap-2 mb-2">
                  <Icon name="world" size={18} class="text-info" />
                  <span class="font-medium text-foreground">Traefik Proxy</span>
                </div>
                <p class="text-xs text-muted-foreground">View routers, services, middlewares. Configure VPN-only access mode.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <div class="flex items-center gap-2 mb-2">
                  <Icon name="route" size={18} class="text-primary" />
                  <span class="font-medium text-foreground">Cross-Network Routing</span>
                </div>
                <p class="text-xs text-muted-foreground">Enable communication between WireGuard and Headscale networks with ACL rules.</p>
              </div>
            </div>
          </div>

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Network Configuration</h3>
            <div class="grid grid-cols-2 gap-4">
              <div class="p-3 bg-muted/50 rounded-lg">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">WireGuard Network</div>
                <code class="text-sm font-mono text-foreground">{routerStatus?.wgIPRange || 'Not configured'}</code>
              </div>
              <div class="p-3 bg-muted/50 rounded-lg">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Headscale Network</div>
                <code class="text-sm font-mono text-foreground">{routerStatus?.headscaleIPRange || 'Not configured'}</code>
              </div>
            </div>
          </div>
        </div>

      <!-- Architecture Tab -->
      {:else if activeTab === 'architecture'}
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">System Architecture</h3>
            <p class="text-sm text-muted-foreground mb-4">
              The admin panel orchestrates multiple containerized services to provide a complete VPN infrastructure.
            </p>
          </div>

          <div class="bg-zinc-900 text-zinc-100 p-6 rounded-lg font-mono text-xs overflow-x-auto">
            <pre class="whitespace-pre">{`
┌─────────────────────────────────────────────────────────────────────┐
│                         Admin Panel (UI + API)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ Traefik  │  │ AdGuard  │  │Headscale │  │WireGuard │            │
│  │  Proxy   │  │   DNS    │  │   VPN    │  │   VPN    │            │
│  │ :443/80  │  │   :53    │  │  :8080   │  │ :51820   │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │             │             │             │                   │
│       └─────────────┴──────┬──────┴─────────────┘                   │
│                            │                                        │
│                     ┌──────┴──────┐                                 │
│                     │  VPN Router │ (Cross-Network)                 │
│                     │ (Tailscale) │                                 │
│                     └──────┬──────┘                                 │
│                            │                                        │
│         ┌──────────────────┴──────────────────┐                    │
│         │                                     │                    │
│   ┌─────┴─────┐                       ┌──────┴──────┐              │
│   │ Headscale │                       │  WireGuard  │              │
│   │  Network  │◄───── ACL Rules ─────►│   Network   │              │
│   │${routerStatus?.headscaleIPRange?.padStart(12) || '100.64.0.0/16'}│                       │${routerStatus?.wgIPRange?.padStart(13) || ' 100.65.0.0/16'}│              │
│   └───────────┘                       └─────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
`}</pre>
          </div>

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Cross-Network Routing</h3>
            <p class="text-sm text-muted-foreground mb-4">
              The VPN Router enables communication between WireGuard and Headscale networks. It runs as a Tailscale container that advertises the WireGuard subnet as a route.
            </p>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <h4 class="font-medium text-foreground mb-2">1. Router Setup</h4>
                <p class="text-xs text-muted-foreground">Tailscale container joins Headscale and advertises WG subnet.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <h4 class="font-medium text-foreground mb-2">2. ACL Rules</h4>
                <p class="text-xs text-muted-foreground">Define which clients can communicate using Headscale ACL + nftables.</p>
              </div>
              <div class="p-4 bg-muted/30 rounded-lg border border-border">
                <h4 class="font-medium text-foreground mb-2">3. Traffic Flow</h4>
                <p class="text-xs text-muted-foreground">Traffic between networks flows through the router based on ACL policy.</p>
              </div>
            </div>
          </div>
        </div>

      <!-- API Reference Tab -->
      {:else if activeTab === 'api'}
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">API Reference</h3>
            <p class="text-sm text-muted-foreground mb-4">
              The API uses JSON for requests/responses. Most endpoints require authentication via Bearer token.
            </p>
          </div>

          <div>
            <h4 class="font-medium text-foreground mb-3 flex items-center gap-2">
              <Badge variant="success" size="sm">Public</Badge>
              No Authentication Required
            </h4>
            <div class="bg-muted/30 rounded-lg overflow-hidden border border-border">
              <table class="w-full text-sm">
                <thead class="bg-muted/50">
                  <tr>
                    <th class="px-4 py-2 text-left font-medium text-foreground">Method</th>
                    <th class="px-4 py-2 text-left font-medium text-foreground">Endpoint</th>
                    <th class="px-4 py-2 text-left font-medium text-foreground">Description</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-border">
                  <tr><td class="px-4 py-2"><Badge variant="info" size="sm">POST</Badge></td><td class="px-4 py-2 font-mono text-xs">/api/auth/login</td><td class="px-4 py-2 text-muted-foreground">Login with username/password</td></tr>
                  <tr><td class="px-4 py-2"><Badge variant="muted" size="sm">GET</Badge></td><td class="px-4 py-2 font-mono text-xs">/api/setup/status</td><td class="px-4 py-2 text-muted-foreground">Get setup wizard status</td></tr>
                  <tr><td class="px-4 py-2"><Badge variant="muted" size="sm">GET</Badge></td><td class="px-4 py-2 font-mono text-xs">/api/setup/detect-headscale</td><td class="px-4 py-2 text-muted-foreground">Auto-detect Headscale URL</td></tr>
                  <tr><td class="px-4 py-2"><Badge variant="info" size="sm">POST</Badge></td><td class="px-4 py-2 font-mono text-xs">/api/setup/test-headscale</td><td class="px-4 py-2 text-muted-foreground">Test Headscale connection</td></tr>
                  <tr><td class="px-4 py-2"><Badge variant="info" size="sm">POST</Badge></td><td class="px-4 py-2 font-mono text-xs">/api/setup/complete</td><td class="px-4 py-2 text-muted-foreground">Complete initial setup</td></tr>
                  <tr><td class="px-4 py-2"><Badge variant="muted" size="sm">GET</Badge></td><td class="px-4 py-2 font-mono text-xs">/health</td><td class="px-4 py-2 text-muted-foreground">Health check endpoint</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h4 class="font-medium text-foreground mb-3 flex items-center gap-2">
              <Badge variant="warning" size="sm">Protected</Badge>
              Requires Bearer Token
            </h4>
            <p class="text-sm text-muted-foreground mb-3">
              Include <code class="bg-muted px-1.5 py-0.5 rounded text-xs">Authorization: Bearer &lt;token&gt;</code> header in requests.
            </p>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">26</div>
                <div class="text-xs text-muted-foreground">Firewall</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">18</div>
                <div class="text-xs text-muted-foreground">Headscale</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">19</div>
                <div class="text-xs text-muted-foreground">AdGuard</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">11</div>
                <div class="text-xs text-muted-foreground">WireGuard</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">11</div>
                <div class="text-xs text-muted-foreground">Traefik</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">7</div>
                <div class="text-xs text-muted-foreground">Docker</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">9</div>
                <div class="text-xs text-muted-foreground">VPN ACL</div>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border text-center">
                <div class="text-2xl font-bold text-foreground">6</div>
                <div class="text-xs text-muted-foreground">Auth/Settings</div>
              </div>
            </div>
          </div>

          <div>
            <h4 class="font-medium text-foreground mb-3">Example: Login</h4>
            <div class="bg-zinc-900 text-zinc-100 p-4 rounded-lg font-mono text-xs overflow-x-auto">
              <pre>{`curl -X POST https://your-domain/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your-password"}'

# Response:
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": { "id": 1, "username": "admin" }
}`}</pre>
            </div>
          </div>

          <div>
            <h4 class="font-medium text-foreground mb-3">Example: List Nodes</h4>
            <div class="bg-zinc-900 text-zinc-100 p-4 rounded-lg font-mono text-xs overflow-x-auto">
              <pre>{`curl https://your-domain/api/vpn/clients \\
  -H "Authorization: Bearer <token>"

# Response:
[
  {
    "id": 1,
    "name": "my-laptop",
    "ip": "100.64.0.1",
    "type": "headscale",
    "rawData": { "online": true, ... }
  },
  ...
]`}</pre>
            </div>
          </div>
        </div>

      <!-- Services Tab -->
      {:else if activeTab === 'services'}
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Service Details</h3>
            <p class="text-sm text-muted-foreground mb-4">
              Each service runs in its own Docker container and is managed through the unified API.
            </p>
          </div>

          <div class="space-y-4">
            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-center gap-3 mb-3">
                <div class="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Icon name="users" size={20} class="text-primary" />
                </div>
                <div>
                  <h4 class="font-medium text-foreground">Headscale</h4>
                  <p class="text-xs text-muted-foreground">Self-hosted Tailscale control server</p>
                </div>
              </div>
              <p class="text-sm text-muted-foreground">
                Headscale is an open source implementation of the Tailscale control server. It allows you to run your own mesh VPN network with NAT traversal, MagicDNS, and automatic key rotation.
              </p>
              <div class="mt-3 flex gap-2">
                <Badge variant="info" size="sm">Mesh VPN</Badge>
                <Badge variant="info" size="sm">NAT Traversal</Badge>
                <Badge variant="info" size="sm">MagicDNS</Badge>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-center gap-3 mb-3">
                <div class="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center">
                  <Icon name="shield" size={20} class="text-success" />
                </div>
                <div>
                  <h4 class="font-medium text-foreground">WireGuard</h4>
                  <p class="text-xs text-muted-foreground">Fast, modern VPN tunnel</p>
                </div>
              </div>
              <p class="text-sm text-muted-foreground">
                WireGuard is a simple, fast VPN that uses state-of-the-art cryptography. It's designed to be lean and performant, with a minimal attack surface.
              </p>
              <div class="mt-3 flex gap-2">
                <Badge variant="success" size="sm">Point-to-Point</Badge>
                <Badge variant="success" size="sm">ChaCha20</Badge>
                <Badge variant="success" size="sm">QR Codes</Badge>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-center gap-3 mb-3">
                <div class="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center">
                  <Icon name="shield-check" size={20} class="text-warning" />
                </div>
                <div>
                  <h4 class="font-medium text-foreground">AdGuard Home</h4>
                  <p class="text-xs text-muted-foreground">Network-wide ad blocking DNS</p>
                </div>
              </div>
              <p class="text-sm text-muted-foreground">
                AdGuard Home is a DNS sinkhole that blocks ads, trackers, and malware at the network level. All VPN clients automatically use it for DNS resolution.
              </p>
              <div class="mt-3 flex gap-2">
                <Badge variant="warning" size="sm">Ad Blocking</Badge>
                <Badge variant="warning" size="sm">Safe Browsing</Badge>
                <Badge variant="warning" size="sm">Query Logging</Badge>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-center gap-3 mb-3">
                <div class="w-10 h-10 rounded-lg bg-info/10 flex items-center justify-center">
                  <Icon name="world" size={20} class="text-info" />
                </div>
                <div>
                  <h4 class="font-medium text-foreground">Traefik</h4>
                  <p class="text-xs text-muted-foreground">Cloud-native reverse proxy</p>
                </div>
              </div>
              <p class="text-sm text-muted-foreground">
                Traefik handles HTTPS termination, routing, and load balancing. It can restrict access to VPN clients only with the VPN-only mode feature.
              </p>
              <div class="mt-3 flex gap-2">
                <Badge variant="info" size="sm">HTTPS</Badge>
                <Badge variant="info" size="sm">VPN-Only Mode</Badge>
                <Badge variant="info" size="sm">Middlewares</Badge>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-center gap-3 mb-3">
                <div class="w-10 h-10 rounded-lg bg-destructive/10 flex items-center justify-center">
                  <Icon name="lock" size={20} class="text-destructive" />
                </div>
                <div>
                  <h4 class="font-medium text-foreground">Firewall (nftables + Fail2Ban)</h4>
                  <p class="text-xs text-muted-foreground">Host-level security</p>
                </div>
              </div>
              <p class="text-sm text-muted-foreground">
                Manages allowed ports with nftables and provides intrusion detection with Fail2Ban. Automatically blocks IPs after repeated failed login attempts.
              </p>
              <div class="mt-3 flex gap-2">
                <Badge variant="danger" size="sm">Port Control</Badge>
                <Badge variant="danger" size="sm">IP Blocking</Badge>
                <Badge variant="danger" size="sm">Fail2Ban Jails</Badge>
              </div>
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>
