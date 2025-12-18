<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet } from '../stores/app.js'
  import { formatTime, formatRelativeDate, formatDuration } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Tabs from '../components/Tabs.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Pagination from '../components/Pagination.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import Button from '../components/Button.svelte'

  let { loading = $bindable(true) } = $props()

  let activeTab = $state('traffic')

  const tabs = [
    { id: 'traffic', label: 'Traffic', icon: 'activity' },
    { id: 'traefik', label: 'Traefik', icon: 'world' },
    { id: 'adguard', label: 'AdGuard', icon: 'shield-check' }
  ]

  // ============ Traffic Tab State ============
  let trafficLogs = $state([])
  let trafficTotal = $state(0)
  let trafficClients = $state([])
  let trafficLoading = $state(false)

  const savedTrafficState = typeof localStorage !== 'undefined'
    ? JSON.parse(localStorage.getItem('traffic') || '{}')
    : {}

  let trafficPage = $state(savedTrafficState.page || 1)
  let trafficPerPage = $state(savedTrafficState.perPage || parseInt(localStorage.getItem('settings_items_per_page') || '25'))
  let trafficSearch = $state(savedTrafficState.search || '')
  let trafficClientFilter = $state(savedTrafficState.client || '')
  let trafficAutoRefresh = $state(false)
  let trafficRefreshInterval = null

  const trafficOffset = $derived((trafficPage - 1) * trafficPerPage)

  $effect(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('traffic', JSON.stringify({
        page: trafficPage,
        perPage: trafficPerPage,
        search: trafficSearch,
        client: trafficClientFilter
      }))
    }
  })

  let trafficSearchTimeout = null
  let trafficSearchQuery = $state(trafficSearch)

  function handleTrafficSearchInput(e) {
    trafficSearchQuery = e.target.value
    clearTimeout(trafficSearchTimeout)
    trafficSearchTimeout = setTimeout(() => {
      trafficSearch = trafficSearchQuery
      trafficPage = 1
      loadTrafficData()
    }, 400)
  }

  async function loadTrafficData() {
    trafficLoading = true
    try {
      const params = new URLSearchParams({
        limit: trafficPerPage.toString(),
        offset: trafficOffset.toString()
      })
      if (trafficSearch) params.set('search', trafficSearch)
      if (trafficClientFilter) params.set('client', trafficClientFilter)

      const res = await apiGet(`/api/fw/traffic?${params}`)
      trafficLogs = res.logs || []
      trafficTotal = res.total || 0
      trafficClients = res.clients || []
    } catch (e) {
      toast('Failed to load traffic: ' + e.message, 'error')
    } finally {
      trafficLoading = false
      loading = false
    }
  }

  function toggleTrafficAutoRefresh() {
    trafficAutoRefresh = !trafficAutoRefresh
    if (trafficAutoRefresh) {
      trafficRefreshInterval = setInterval(loadTrafficData, 5000)
    } else {
      clearInterval(trafficRefreshInterval)
      trafficRefreshInterval = null
    }
  }

  // ============ Traefik Tab State ============
  let traefikLogs = $state([])
  let traefikSearch = $state('')
  let traefikLoading = $state(false)

  async function loadTraefikLogs() {
    traefikLoading = true
    try {
      traefikLogs = await apiGet('/api/traefik/logs?limit=100')
    } catch (e) {
      toast('Failed to load logs: ' + e.message, 'error')
    } finally {
      traefikLoading = false
      loading = false
    }
  }

  const filteredTraefikLogs = $derived(
    traefikLogs.filter(log => {
      if (!traefikSearch) return true
      const q = traefikSearch.toLowerCase()
      return (
        log.path?.toLowerCase().includes(q) ||
        log.clientIP?.toLowerCase().includes(q) ||
        log.method?.toLowerCase().includes(q) ||
        String(log.status).includes(q)
      )
    })
  )

  // ============ AdGuard Tab State ============
  let adguardLogs = $state([])
  let adguardSearch = $state('')
  let adguardLoading = $state(false)

  function getAdGuardStatusInfo(log) {
    const reason = log.reason || ''
    const rules = log.rules || []
    const serviceName = rules.find(r => r.filter_list_id === -1)?.text || ''

    switch (reason) {
      case 'NotFilteredNotFound':
      case 'NotFilteredAllowList':
        return { label: 'Processed', variant: 'success' }
      case 'NotFilteredWhiteList':
        return { label: 'Allowed', variant: 'success' }
      case 'NotFilteredError':
        return { label: 'Error', variant: 'warning' }
      case 'FilteredBlockList':
        return { label: 'Blocked', variant: 'danger' }
      case 'FilteredSafeBrowsing':
        return { label: 'Blocked Threats', variant: 'danger' }
      case 'FilteredParental':
        return { label: 'Blocked by Parental', variant: 'danger' }
      case 'FilteredBlockedService':
        return { label: serviceName ? `Blocked (${serviceName})` : 'Blocked Service', variant: 'danger' }
      case 'FilteredSafeSearch':
        return { label: 'Safe Search', variant: 'info' }
      case 'Rewrite':
      case 'RewriteEtcHosts':
      case 'RewriteRule':
        return { label: 'Rewritten', variant: 'info' }
      default:
        if (reason.startsWith('Filtered')) {
          return { label: 'Filtered', variant: 'warning' }
        }
        return { label: reason || 'Unknown', variant: 'secondary' }
    }
  }

  async function loadAdGuardLogs() {
    adguardLoading = true
    try {
      const res = await apiGet('/api/adguard/querylog?limit=100')
      adguardLogs = res?.data || []
    } catch (e) {
      toast('Failed to load logs: ' + e.message, 'error')
    } finally {
      adguardLoading = false
      loading = false
    }
  }

  const filteredAdGuardLogs = $derived(
    adguardLogs.filter(log => {
      if (!adguardSearch) return true
      const q = adguardSearch.toLowerCase()
      return (
        log.question?.name?.toLowerCase().includes(q) ||
        log.client?.toLowerCase().includes(q) ||
        log.question?.type?.toLowerCase().includes(q)
      )
    })
  )

  // ============ Tab Loading ============
  let loadedTabs = $state({})

  $effect(() => {
    if (activeTab && !loadedTabs[activeTab]) {
      loadedTabs[activeTab] = true
      if (activeTab === 'traffic') loadTrafficData()
      else if (activeTab === 'traefik') loadTraefikLogs()
      else if (activeTab === 'adguard') loadAdGuardLogs()
    }
  })

  onMount(() => {
    // Initial load handled by $effect
  })

  onDestroy(() => {
    if (trafficRefreshInterval) clearInterval(trafficRefreshInterval)
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="file-text"
    title="Logs"
    description="View traffic logs, HTTP access logs from Traefik, and DNS query logs from AdGuard."
  />

  <!-- Tabs -->
  <div class="bg-card border border-border rounded-lg overflow-hidden">
    <Tabs {tabs} bind:activeTab urlKey="tab" />

    <div class="p-5">
      <!-- Traffic Tab -->
      {#if activeTab === 'traffic'}
        <div class="space-y-4">
          <!-- Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-col sm:flex-row sm:items-center gap-3">
              <!-- Search & Filter -->
              <div class="flex flex-col sm:flex-row gap-3 flex-1">
                <Input
                  type="search"
                  value={trafficSearchQuery}
                  oninput={handleTrafficSearchInput}
                  placeholder="Search IP, hostname..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
                {#if trafficClients.length > 0}
                  <Select
                    value={trafficClientFilter}
                    onchange={(e) => { trafficClientFilter = e.target.value; trafficPage = 1; loadTrafficData() }}
                    class="sm:w-40"
                  >
                    <option value="">All clients</option>
                    {#each trafficClients as client}
                      <option value={client}>{client}</option>
                    {/each}
                  </Select>
                {/if}
              </div>

              <!-- Action buttons -->
              <div class="kt-btn-group self-end sm:self-auto">
                <Button
                  variant={trafficAutoRefresh ? 'mono' : 'outline'}
                  size="sm"
                  icon={trafficAutoRefresh ? 'player-pause' : 'player-play'}
                  onclick={toggleTrafficAutoRefresh}
                >
                  {trafficAutoRefresh ? 'Pause' : 'Auto'}
                </Button>
                <Button variant="outline" size="sm" icon="refresh" onclick={loadTrafficData}>
                  Refresh
                </Button>
              </div>
            </div>
          </div>

          {#if trafficLoading && trafficLogs.length === 0}
            <LoadingSpinner size="lg" centered />
          {:else if trafficLogs.length === 0}
            <EmptyState
              icon="activity"
              title="No traffic logs"
              description={trafficSearch ? 'No results match your search' : 'Traffic will appear when VPN clients connect'}
            />
          {:else}
            <div class="kt-table-wrapper rounded-lg border border-border bg-card overflow-hidden">
              <table class="kt-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {#each trafficLogs as log}
                    <tr>
                      <td class="whitespace-nowrap text-muted-foreground">{formatRelativeDate(log.timestamp)}</td>
                      <td><code class="text-xs font-mono">{log.src_ip}</code></td>
                      <td><code class="text-xs font-mono">{log.dest_ip}</code></td>
                      <td><Badge variant="info" size="sm">{log.dest_port}</Badge></td>
                      <td><Badge variant="muted" size="sm">{log.protocol?.toUpperCase()}</Badge></td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>

            <Pagination
              bind:page={trafficPage}
              bind:perPage={trafficPerPage}
              total={trafficTotal}
              onPageChange={loadTrafficData}
            />
          {/if}
        </div>

      <!-- Traefik Tab -->
      {:else if activeTab === 'traefik'}
        <div class="space-y-4">
          <!-- Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-col sm:flex-row sm:items-center gap-3">
              <!-- Search -->
              <div class="flex-1">
                <Input
                  type="search"
                  bind:value={traefikSearch}
                  placeholder="Search path, client IP, method..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
              </div>

              <!-- Action buttons -->
              <div class="kt-btn-group self-end sm:self-auto">
                <Button variant="outline" size="sm" icon="refresh" onclick={loadTraefikLogs}>
                  Refresh
                </Button>
              </div>
            </div>
          </div>

          {#if traefikLoading && traefikLogs.length === 0}
            <LoadingSpinner size="lg" centered />
          {:else if filteredTraefikLogs.length === 0}
            <EmptyState
              icon="file-text"
              title="No Logs Yet"
              description={traefikSearch ? 'No results match your search' : 'Access logs will appear when requests are made'}
            />
          {:else}
            <div class="kt-table-wrapper rounded-lg border border-border bg-card overflow-hidden">
              <table class="kt-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Client</th>
                  </tr>
                </thead>
                <tbody>
                  {#each filteredTraefikLogs as log}
                    <tr>
                      <td class="whitespace-nowrap">{formatTime(log.time)}</td>
                      <td>
                        <Badge variant={log.method === 'GET' ? 'info' : log.method === 'POST' ? 'success' : 'muted'} size="sm">
                          {log.method}
                        </Badge>
                      </td>
                      <td><code class="text-xs font-mono">{log.path}</code></td>
                      <td>
                        <Badge variant={log.status < 300 ? 'success' : log.status < 400 ? 'info' : 'danger'} size="sm">
                          {log.status}
                        </Badge>
                      </td>
                      <td>{formatDuration(log.duration)}</td>
                      <td><code class="text-xs font-mono text-muted-foreground">{log.clientIP}</code></td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>

      <!-- AdGuard Tab -->
      {:else if activeTab === 'adguard'}
        <div class="space-y-4">
          <!-- Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-col sm:flex-row sm:items-center gap-3">
              <!-- Search -->
              <div class="flex-1">
                <Input
                  type="search"
                  bind:value={adguardSearch}
                  placeholder="Search domains, clients..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
              </div>

              <!-- Action buttons -->
              <div class="kt-btn-group self-end sm:self-auto">
                <Button variant="outline" size="sm" icon="refresh" onclick={loadAdGuardLogs}>
                  Refresh
                </Button>
              </div>
            </div>
          </div>

          {#if adguardLoading && adguardLogs.length === 0}
            <LoadingSpinner size="lg" centered />
          {:else if filteredAdGuardLogs.length === 0}
            <EmptyState
              icon="list"
              title="No DNS Queries"
              description={adguardSearch ? 'No results match your search' : 'Waiting for VPN clients to make DNS requests...'}
            />
          {:else}
            <div class="kt-table-wrapper rounded-lg border border-border bg-card overflow-hidden">
              <table class="kt-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Client</th>
                    <th>Domain</th>
                    <th>Type</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {#each filteredAdGuardLogs as log}
                    {@const status = getAdGuardStatusInfo(log)}
                    <tr>
                      <td class="whitespace-nowrap">{formatTime(log.time)}</td>
                      <td><code class="text-xs font-mono text-muted-foreground">{log.client || '-'}</code></td>
                      <td><code class="text-xs font-mono {status.variant === 'danger' ? 'text-destructive' : ''}">{log.question?.name || '-'}</code></td>
                      <td><Badge variant="info" size="sm">{log.question?.type || 'A'}</Badge></td>
                      <td><Badge variant={status.variant} size="sm">{status.label}</Badge></td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </div>
</div>
