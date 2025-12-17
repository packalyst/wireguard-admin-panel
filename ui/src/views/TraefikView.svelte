<script>
  import { onMount } from 'svelte'
  import { toast, apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Tabs from '../components/Tabs.svelte'

  let { loading = $bindable(true) } = $props()

  let routers = $state([])
  let services = $state([])
  let middlewares = $state([])
  let overview = $state(null)
  let activeTab = $state('overview')

  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'layout' },
    { id: 'routers', label: 'Routers', icon: 'git-branch' },
    { id: 'services', label: 'Services', icon: 'server' },
    { id: 'middlewares', label: 'Middlewares', icon: 'shield' }
  ]

  async function loadData() {
    try {
      const [routersRes, servicesRes, middlewaresRes, overviewRes] = await Promise.all([
        apiGet('/api/traefik/http/routers').catch(() => []),
        apiGet('/api/traefik/http/services').catch(() => []),
        apiGet('/api/traefik/http/middlewares').catch(() => []),
        apiGet('/api/traefik/overview').catch(() => null)
      ])
      routers = Array.isArray(routersRes) ? routersRes : Object.entries(routersRes || {}).map(([name, r]) => ({ ...r, name }))
      services = Array.isArray(servicesRes) ? servicesRes : Object.entries(servicesRes || {}).map(([name, s]) => ({ ...s, name }))
      middlewares = Array.isArray(middlewaresRes) ? middlewaresRes : Object.entries(middlewaresRes || {}).map(([name, m]) => ({ ...m, name }))
      overview = overviewRes
    } catch (e) {
      toast('Failed to load Traefik data: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // Stats
  const activeRouters = $derived(routers.filter(r => r.status === 'enabled').length)

  // Get middleware type
  function getMiddlewareType(mw) {
    if (mw.rateLimit) return 'Rate Limit'
    if (mw.headers) return 'Headers'
    if (mw.ipAllowList || mw.ipWhiteList) return 'IP Allowlist'
    if (mw.basicAuth) return 'Basic Auth'
    if (mw.replacePathRegex || mw.replacePath) return 'Path Rewrite'
    if (mw.stripPrefix) return 'Strip Prefix'
    return 'Custom'
  }

  function getMiddlewareConfig(mw) {
    if (mw.rateLimit) return `${mw.rateLimit.average}/s avg, ${mw.rateLimit.burst} burst`
    if (mw.headers) {
      const parts = []
      if (mw.headers.frameDeny) parts.push('X-Frame-Options')
      if (mw.headers.contentTypeNosniff) parts.push('X-Content-Type')
      if (mw.headers.browserXssFilter) parts.push('XSS-Filter')
      return parts.join(', ') || 'Custom headers'
    }
    if (mw.ipAllowList) return `${mw.ipAllowList.sourceRange?.length || 0} ranges`
    if (mw.replacePathRegex) return mw.replacePathRegex.regex
    return '-'
  }

  onMount(loadData)
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="route" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Traefik Reverse Proxy</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Manage your reverse proxy configuration. Monitor routers, services, and middlewares.
          Configure rate limiting, security headers, and IP allowlists for protection.
        </p>
      </div>
    </div>
  </div>

  {#if loading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    </div>
  {:else}
    <!-- Stats Grid -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-info/10 flex items-center justify-center flex-shrink-0">
          <Icon name="git-branch" size={20} class="text-info" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{routers.length}</div>
          <div class="text-[11px] text-muted-foreground">Routers</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
          <Icon name="server" size={20} class="text-primary" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{services.length}</div>
          <div class="text-[11px] text-muted-foreground">Services</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center flex-shrink-0">
          <Icon name="shield" size={20} class="text-warning" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{middlewares.length}</div>
          <div class="text-[11px] text-muted-foreground">Middlewares</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center flex-shrink-0">
          <Icon name="check" size={20} class="text-success" />
        </div>
        <div>
          <div class="text-2xl font-bold text-success">{activeRouters}</div>
          <div class="text-[11px] text-muted-foreground">Active</div>
        </div>
      </div>
    </div>

    <!-- Tabs -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <Tabs {tabs} bind:activeTab urlKey="tab" />

      <div class="p-5">
        <!-- Overview Tab -->
        {#if activeTab === 'overview'}
          <div class="space-y-6">
            <!-- Active Protections -->
            <div>
              <h4 class="text-sm font-semibold text-foreground mb-3">Active Protections</h4>
              <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div class="flex items-center gap-3 p-3 bg-success/10 border border-success/20 rounded-lg">
                  <Icon name="shield-check" size={18} class="text-success" />
                  <div>
                    <div class="text-xs font-medium text-foreground">Rate Limiting</div>
                    <div class="text-[10px] text-muted-foreground">Enabled</div>
                  </div>
                </div>
                <div class="flex items-center gap-3 p-3 bg-success/10 border border-success/20 rounded-lg">
                  <Icon name="file-text" size={18} class="text-success" />
                  <div>
                    <div class="text-xs font-medium text-foreground">Access Logging</div>
                    <div class="text-[10px] text-muted-foreground">JSON format</div>
                  </div>
                </div>
                <div class="flex items-center gap-3 p-3 bg-success/10 border border-success/20 rounded-lg">
                  <Icon name="lock" size={18} class="text-success" />
                  <div>
                    <div class="text-xs font-medium text-foreground">Security Headers</div>
                    <div class="text-[10px] text-muted-foreground">XSS protection</div>
                  </div>
                </div>
                <div class="flex items-center gap-3 p-3 bg-success/10 border border-success/20 rounded-lg">
                  <Icon name="globe" size={18} class="text-success" />
                  <div>
                    <div class="text-xs font-medium text-foreground">IP Allowlist</div>
                    <div class="text-[10px] text-muted-foreground">VPN only</div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Routing Overview as Cards -->
            <div>
              <h4 class="text-sm font-semibold text-foreground mb-3">Routing Overview</h4>
              {#if routers.filter(r => !r.name.includes('@internal')).length > 0}
                <div class="grid gap-2">
                  {#each routers.filter(r => !r.name.includes('@internal')) as router}
                    {@const hasProtection = router.middlewares?.filter(m => !m.includes('rewrite')).length > 0}
                    <div class="flex items-center gap-3 p-3 bg-muted/30 border border-border rounded-lg hover:border-primary/30 transition-colors">
                      <div class="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 {hasProtection ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                        <Icon name={hasProtection ? 'shield-check' : 'route'} size={16} />
                      </div>
                      <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                          <code class="text-xs font-mono text-foreground bg-muted px-1.5 py-0.5 rounded">{router.rule?.replace('PathPrefix(`', '').replace('`)', '') || '-'}</code>
                          <Icon name="arrow-right" size={12} class="text-muted-foreground" />
                          <span class="text-xs text-muted-foreground truncate">{router.service || '-'}</span>
                        </div>
                        {#if router.middlewares?.filter(m => !m.includes('rewrite')).length}
                          <div class="flex flex-wrap gap-1 mt-1">
                            {#each router.middlewares.filter(m => !m.includes('rewrite')) as mw}
                              <span class="text-[10px] px-1.5 py-0.5 rounded bg-success/10 text-success">{mw.split('@')[0]}</span>
                            {/each}
                          </div>
                        {/if}
                      </div>
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-8 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
                  <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
                    <Icon name="route" size={20} />
                  </div>
                  <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No Routes</h4>
                  <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Routes will appear when configured</p>
                </div>
              {/if}
            </div>
          </div>

        <!-- Routers Tab -->
        {:else if activeTab === 'routers'}
          {#if routers.length === 0}
            <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
                <Icon name="git-branch" size={20} />
              </div>
              <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No Routers</h4>
              <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Routers will appear when configured in Traefik</p>
            </div>
          {:else}
            <div class="grid gap-3 md:grid-cols-2">
              {#each routers as router}
                <div class="p-3 bg-muted/30 border border-border rounded-lg">
                  <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                      <div class="w-8 h-8 rounded-lg flex items-center justify-center bg-info/10 text-info flex-shrink-0">
                        <Icon name="git-branch" size={16} />
                      </div>
                      <span class="text-sm font-medium text-foreground truncate">{router.name}</span>
                    </div>
                    <Badge variant={router.status === 'enabled' ? 'success' : 'danger'} size="sm">
                      {router.status || 'unknown'}
                    </Badge>
                  </div>
                  <div class="space-y-1.5 text-xs pl-10">
                    {#if router.rule}
                      <code class="block px-2 py-1 bg-muted rounded font-mono text-[11px] break-all">{router.rule}</code>
                    {/if}
                    {#if router.service}
                      <div class="flex items-center gap-1.5 text-muted-foreground">
                        <Icon name="arrow-right" size={12} />
                        <span>{router.service}</span>
                      </div>
                    {/if}
                    {#if router.middlewares?.length}
                      <div class="flex flex-wrap gap-1">
                        {#each router.middlewares as mw}
                          <span class="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{mw}</span>
                        {/each}
                      </div>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {/if}

        <!-- Services Tab -->
        {:else if activeTab === 'services'}
          {#if services.length === 0}
            <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
                <Icon name="server" size={20} />
              </div>
              <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No Services</h4>
              <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Services will appear when configured in Traefik</p>
            </div>
          {:else}
            <div class="grid gap-3 md:grid-cols-2">
              {#each services as service}
                <div class="p-3 bg-muted/30 border border-border rounded-lg">
                  <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                      <div class="w-8 h-8 rounded-lg flex items-center justify-center bg-primary/10 text-primary flex-shrink-0">
                        <Icon name="server" size={16} />
                      </div>
                      <span class="text-sm font-medium text-foreground truncate">{service.name}</span>
                    </div>
                    <Badge variant={service.status === 'enabled' ? 'success' : 'warning'} size="sm">
                      {service.status || 'loadbalancer'}
                    </Badge>
                  </div>
                  {#if service.loadBalancer?.servers?.length}
                    <div class="space-y-1 pl-10">
                      {#each service.loadBalancer.servers as server}
                        <code class="block px-2 py-1 bg-muted rounded font-mono text-[11px]">{server.url || server.address}</code>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}

        <!-- Middlewares Tab -->
        {:else if activeTab === 'middlewares'}
          {#if middlewares.length === 0}
            <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
                <Icon name="shield" size={20} />
              </div>
              <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No Middlewares</h4>
              <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Middlewares will appear when configured in Traefik</p>
            </div>
          {:else}
            <div class="grid gap-3 md:grid-cols-2">
              {#each middlewares as mw}
                <div class="p-3 bg-muted/30 border border-border rounded-lg">
                  <div class="flex items-center justify-between mb-1">
                    <div class="flex items-center gap-2">
                      <div class="w-8 h-8 rounded-lg flex items-center justify-center bg-warning/10 text-warning flex-shrink-0">
                        <Icon name="shield" size={16} />
                      </div>
                      <span class="text-sm font-medium text-foreground truncate">{mw.name}</span>
                    </div>
                    <Badge variant="info" size="sm">{getMiddlewareType(mw)}</Badge>
                  </div>
                  <div class="text-xs text-muted-foreground pl-10">{getMiddlewareConfig(mw)}</div>
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      </div>
    </div>
  {/if}
</div>
