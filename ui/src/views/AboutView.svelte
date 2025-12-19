<script>
  import { onMount } from 'svelte'
  import { apiGet, getInitialTab } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Tabs from '../components/Tabs.svelte'

  let { loading = $bindable(true) } = $props()

  let activeTab = $state(getInitialTab('overview', ['overview', 'api', 'services']))
  let routerStatus = $state(null)
  let expandedApi = $state(null)
  let apiSchema = $state(null)

  // Service display config (icons, colors, order)
  const serviceConfig = {
    auth: { name: 'Authentication', icon: 'key', color: 'primary', order: 1 },
    headscale: { name: 'Headscale', icon: 'users', color: 'primary', order: 2 },
    firewall: { name: 'Firewall', icon: 'shield', color: 'destructive', order: 3 },
    adguard: { name: 'AdGuard', icon: 'shield-check', color: 'warning', order: 4 },
    traefik: { name: 'Traefik', icon: 'world', color: 'info', order: 5 },
    docker: { name: 'Docker', icon: 'box', color: 'info', order: 6 },
    geolocation: { name: 'Geolocation', icon: 'globe', color: 'primary', order: 7 },
    vpn: { name: 'VPN ACL', icon: 'route', color: 'success', order: 8 },
    wireguard: { name: 'WireGuard', icon: 'shield-lock', color: 'success', order: 9 },
    settings: { name: 'Settings', icon: 'settings', color: 'muted', order: 10 },
    setup: { name: 'Setup', icon: 'wand', color: 'muted', order: 11 }
  }

  // Transform API schema for display
  let apiServices = $derived(
    apiSchema?.services
      ? Object.entries(apiSchema.services)
          .map(([id, svc]) => ({
            id,
            name: serviceConfig[id]?.name || id,
            prefix: svc.prefix,
            icon: serviceConfig[id]?.icon || 'server',
            color: serviceConfig[id]?.color || 'muted',
            order: serviceConfig[id]?.order || 99,
            endpoints: svc.endpoints.map(ep => ({
              method: ep.methods[0],
              path: ep.path.replace(svc.prefix, ''),
              desc: ep.description
            }))
          }))
          .sort((a, b) => a.order - b.order)
      : []
  )

  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'info-circle' },
    { id: 'api', label: 'API Reference', icon: 'code' },
    { id: 'services', label: 'Services', icon: 'server' }
  ]

  onMount(async () => {
    try {
      const [router, schema] = await Promise.all([
        apiGet('/api/vpn/router/status').catch(() => null),
        apiGet('/api').catch(() => null)
      ])
      routerStatus = router
      apiSchema = schema
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

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">System Architecture</h3>
            <div class="bg-zinc-900 text-zinc-100 p-4 rounded-lg font-mono text-[10px] overflow-x-auto">
              <pre class="whitespace-pre">{`┌─────────────────────────────────────────────────────────────────────┐
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
└─────────────────────────────────────────────────────────────────────┘`}</pre>
            </div>
          </div>
        </div>

      <!-- API Reference Tab -->
      {:else if activeTab === 'api'}
        {@const examples = [
          { title: 'Login', method: 'POST', endpoint: '/api/auth/login',
            request: `{
  "username": "admin",
  "password": "your-password"
}`,
            response: `{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": { "id": 1, "username": "admin" }
}` },
          { title: 'List Nodes', method: 'GET', endpoint: '/api/hs/nodes',
            request: null,
            response: `{
  "nodes": [
    {
      "id": "1",
      "name": "laptop",
      "ipAddresses": ["100.64.0.1"],
      "online": true,
      "user": { "name": "admin" }
    }
  ]
}` },
          { title: 'Block IP', method: 'POST', endpoint: '/api/fw/blocked',
            request: `{
  "ip": "192.168.1.100",
  "reason": "Suspicious activity",
  "source": "manual"
}`,
            response: `{
  "success": true,
  "message": "IP blocked"
}` },
          { title: 'Toggle Protection', method: 'PUT', endpoint: '/api/adguard/config',
            request: `{
  "type": "protection",
  "enabled": true
}`,
            response: `{
  "success": true
}` }
        ]}
        {@const methodColors = { GET: 'muted', POST: 'info', PUT: 'warning', DELETE: 'danger' }}

        <div class="space-y-4">
          <!-- Header -->
          <div class="flex items-center justify-between">
            <p class="text-sm text-muted-foreground">
              RESTful API with JSON. Include <code class="bg-muted px-1.5 py-0.5 rounded text-xs">Authorization: Bearer &lt;token&gt;</code> header.
            </p>
            <div class="text-xs text-muted-foreground">
              {apiServices?.reduce((acc, s) => acc + s.endpoints.length, 0) || 0} endpoints
            </div>
          </div>

          <!-- API Services Grid -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            {#if !apiSchema}
              {#each Array(6) as _}
                <div class="bg-muted/30 rounded-lg border border-border p-3 animate-pulse">
                  <div class="flex items-center gap-2">
                    <div class="w-7 h-7 rounded bg-muted"></div>
                    <div class="flex-1">
                      <div class="h-4 w-24 bg-muted rounded mb-1"></div>
                      <div class="h-3 w-16 bg-muted rounded"></div>
                    </div>
                  </div>
                </div>
              {/each}
            {:else}
            {#each apiServices as service}
              <div class="bg-muted/30 rounded-lg border border-border overflow-hidden">
                <button
                  onclick={() => expandedApi = expandedApi === service.id ? null : service.id}
                  class="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors cursor-pointer"
                >
                  <div class="flex items-center gap-2">
                    <div class="w-7 h-7 rounded bg-{service.color}/10 flex items-center justify-center">
                      <Icon name={service.icon} size={14} class="text-{service.color}" />
                    </div>
                    <div class="text-left">
                      <div class="font-medium text-foreground text-sm">{service.name}</div>
                      <div class="text-[10px] text-muted-foreground font-mono">{service.prefix}</div>
                    </div>
                  </div>
                  <div class="flex items-center gap-2">
                    <span class="text-xs text-muted-foreground">{service.endpoints.length}</span>
                    <Icon name={expandedApi === service.id ? 'chevron-down' : 'chevron-right'} size={14} class="text-muted-foreground" />
                  </div>
                </button>

                {#if expandedApi === service.id}
                  <div class="border-t border-border">
                    <table class="w-full text-xs">
                      <tbody class="divide-y divide-border/50">
                        {#each service.endpoints as ep}
                          <tr class="hover:bg-muted/30">
                            <td class="px-3 py-1.5 w-16">
                              <Badge variant={methodColors[ep.method]} size="sm">{ep.method}</Badge>
                            </td>
                            <td class="px-2 py-1.5 font-mono text-foreground">{ep.path}</td>
                            <td class="px-3 py-1.5 text-muted-foreground hidden sm:table-cell">{ep.desc}</td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {/if}
              </div>
            {/each}
            {/if}
          </div>

          <!-- Examples -->
          <div class="pt-2">
            <h4 class="font-medium text-foreground mb-3 flex items-center gap-2">
              <Icon name="code" size={16} class="text-muted-foreground" />
              Examples
            </h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              {#each examples as ex}
                <div class="bg-muted/30 rounded-lg border border-border overflow-hidden">
                  <div class="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/50">
                    <Badge variant={methodColors[ex.method]} size="sm">{ex.method}</Badge>
                    <span class="font-mono text-xs text-foreground">{ex.endpoint}</span>
                  </div>
                  <div class="p-3 space-y-2">
                    {#if ex.request}
                      <div>
                        <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Request</div>
                        <pre class="bg-zinc-900 text-zinc-100 p-2 rounded text-[10px] font-mono overflow-x-auto">{ex.request}</pre>
                      </div>
                    {/if}
                    <div>
                      <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Response</div>
                      <pre class="bg-zinc-900 text-zinc-100 p-2 rounded text-[10px] font-mono overflow-x-auto">{ex.response}</pre>
                    </div>
                  </div>
                </div>
              {/each}
            </div>
          </div>
        </div>

      <!-- Services Tab -->
      {:else if activeTab === 'services'}
        <div class="space-y-4">
          <p class="text-sm text-muted-foreground">
            Each service runs in its own Docker container and is managed through the unified API.
          </p>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-start gap-3">
                <div class="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon name="users" size={16} class="text-primary" />
                </div>
                <div class="flex-1 min-w-0">
                  <h4 class="font-medium text-foreground">Headscale</h4>
                  <p class="text-xs text-muted-foreground mb-2">Self-hosted Tailscale control server</p>
                  <p class="text-xs text-muted-foreground/80 leading-relaxed">
                    Open source Tailscale control server. Run your own mesh VPN with NAT traversal, MagicDNS, and automatic key rotation.
                  </p>
                  <div class="mt-2 flex flex-wrap gap-1">
                    <Badge variant="info" size="sm">Mesh VPN</Badge>
                    <Badge variant="info" size="sm">NAT Traversal</Badge>
                    <Badge variant="info" size="sm">MagicDNS</Badge>
                  </div>
                </div>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-start gap-3">
                <div class="w-8 h-8 rounded-lg bg-success/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon name="shield" size={16} class="text-success" />
                </div>
                <div class="flex-1 min-w-0">
                  <h4 class="font-medium text-foreground">WireGuard</h4>
                  <p class="text-xs text-muted-foreground mb-2">Fast, modern VPN tunnel</p>
                  <p class="text-xs text-muted-foreground/80 leading-relaxed">
                    Simple, fast VPN using state-of-the-art cryptography. Lean and performant with minimal attack surface.
                  </p>
                  <div class="mt-2 flex flex-wrap gap-1">
                    <Badge variant="success" size="sm">Point-to-Point</Badge>
                    <Badge variant="success" size="sm">ChaCha20</Badge>
                    <Badge variant="success" size="sm">QR Codes</Badge>
                  </div>
                </div>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-start gap-3">
                <div class="w-8 h-8 rounded-lg bg-warning/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon name="shield-check" size={16} class="text-warning" />
                </div>
                <div class="flex-1 min-w-0">
                  <h4 class="font-medium text-foreground">AdGuard Home</h4>
                  <p class="text-xs text-muted-foreground mb-2">Network-wide ad blocking DNS</p>
                  <p class="text-xs text-muted-foreground/80 leading-relaxed">
                    DNS sinkhole blocking ads, trackers, and malware at network level. All VPN clients use it automatically.
                  </p>
                  <div class="mt-2 flex flex-wrap gap-1">
                    <Badge variant="warning" size="sm">Ad Blocking</Badge>
                    <Badge variant="warning" size="sm">Safe Browsing</Badge>
                    <Badge variant="warning" size="sm">Query Log</Badge>
                  </div>
                </div>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-start gap-3">
                <div class="w-8 h-8 rounded-lg bg-info/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon name="world" size={16} class="text-info" />
                </div>
                <div class="flex-1 min-w-0">
                  <h4 class="font-medium text-foreground">Traefik</h4>
                  <p class="text-xs text-muted-foreground mb-2">Cloud-native reverse proxy</p>
                  <p class="text-xs text-muted-foreground/80 leading-relaxed">
                    HTTPS termination, routing, and load balancing. Restrict access to VPN clients with VPN-only mode.
                  </p>
                  <div class="mt-2 flex flex-wrap gap-1">
                    <Badge variant="info" size="sm">HTTPS</Badge>
                    <Badge variant="info" size="sm">VPN-Only</Badge>
                    <Badge variant="info" size="sm">Middlewares</Badge>
                  </div>
                </div>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-start gap-3">
                <div class="w-8 h-8 rounded-lg bg-destructive/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon name="lock" size={16} class="text-destructive" />
                </div>
                <div class="flex-1 min-w-0">
                  <h4 class="font-medium text-foreground">Firewall</h4>
                  <p class="text-xs text-muted-foreground mb-2">nftables + custom jails</p>
                  <p class="text-xs text-muted-foreground/80 leading-relaxed">
                    Port management with nftables. Custom jails auto-block IPs after repeated failed connection attempts.
                  </p>
                  <div class="mt-2 flex flex-wrap gap-1">
                    <Badge variant="danger" size="sm">Port Control</Badge>
                    <Badge variant="danger" size="sm">IP Blocking</Badge>
                    <Badge variant="danger" size="sm">Jails</Badge>
                  </div>
                </div>
              </div>
            </div>

            <div class="p-4 bg-muted/30 rounded-lg border border-border">
              <div class="flex items-start gap-3">
                <div class="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon name="globe" size={16} class="text-primary" />
                </div>
                <div class="flex-1 min-w-0">
                  <h4 class="font-medium text-foreground">Geolocation</h4>
                  <p class="text-xs text-muted-foreground mb-2">IP-based country lookup</p>
                  <p class="text-xs text-muted-foreground/80 leading-relaxed">
                    Identify traffic origin by country. Block connections from specific countries with country-based firewall rules.
                  </p>
                  <div class="mt-2 flex flex-wrap gap-1">
                    <Badge variant="info" size="sm">IP Lookup</Badge>
                    <Badge variant="info" size="sm">Country Block</Badge>
                    <Badge variant="info" size="sm">Traffic Logs</Badge>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Cross-Network Routing -->
          <div class="pt-2">
            <h4 class="font-medium text-foreground mb-3 flex items-center gap-2">
              <Icon name="route" size={16} class="text-muted-foreground" />
              Cross-Network Routing
            </h4>
            <p class="text-xs text-muted-foreground mb-3">
              VPN Router enables communication between WireGuard and Headscale networks via Tailscale container.
            </p>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div class="p-3 bg-muted/30 rounded-lg border border-border">
                <h5 class="text-sm font-medium text-foreground mb-1">1. Router Setup</h5>
                <p class="text-xs text-muted-foreground">Tailscale container joins Headscale and advertises WG subnet.</p>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border">
                <h5 class="text-sm font-medium text-foreground mb-1">2. ACL Rules</h5>
                <p class="text-xs text-muted-foreground">Define which clients can communicate using Headscale ACL + nftables.</p>
              </div>
              <div class="p-3 bg-muted/30 rounded-lg border border-border">
                <h5 class="text-sm font-medium text-foreground mb-1">3. Traffic Flow</h5>
                <p class="text-xs text-muted-foreground">Traffic between networks flows through the router based on ACL policy.</p>
              </div>
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>
