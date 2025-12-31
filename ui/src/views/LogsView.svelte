<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, getInitialTab } from '../stores/app.js'
  import { lookupIPs, getGeoCache } from '../stores/geo.js'
  import { loadState, saveState, createDebouncedSearch, getDefaultPerPage } from '../stores/helpers.js'
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
  import CountryFlag from '../components/CountryFlag.svelte'

  let { loading = $bindable(true) } = $props()

  let activeTab = $state(getInitialTab('traffic', ['traffic', 'traefik', 'adguard']))

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
  let geoData = $state({})  // IP -> geo result map (from geo.js cache)

  const savedTrafficState = loadState('traffic')

  let trafficPage = $state(savedTrafficState.page || 1)
  let trafficPerPage = $state(savedTrafficState.perPage || getDefaultPerPage())
  let trafficSearch = $state(savedTrafficState.search || '')
  let trafficClientFilter = $state(savedTrafficState.client || '')
  let trafficAutoRefresh = $state(false)
  let trafficRefreshInterval = null
  let trafficSearchQuery = $state(savedTrafficState.search || '')

  const trafficOffset = $derived((trafficPage - 1) * trafficPerPage)

  // Save state to localStorage
  $effect(() => {
    saveState('traffic', {
      page: trafficPage,
      perPage: trafficPerPage,
      search: trafficSearch,
      client: trafficClientFilter
    })
  })

  // Debounced search
  const debouncedTrafficSearch = createDebouncedSearch((value) => {
    trafficSearch = value
    trafficPage = 1
    loadTrafficData()
  })

  function handleTrafficSearchInput(e) {
    trafficSearchQuery = e.target.value
    debouncedTrafficSearch(trafficSearchQuery)
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

      // Enrich with geo data (helper handles caching and availability check)
      if (trafficLogs.length > 0) {
        const ips = trafficLogs.map(l => l.dest_ip).filter(Boolean)
        geoData = await lookupIPs(ips)
      }
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
    // Initial data load handled by $effect
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
        <div class="data-table">
          <!-- Header -->
          <div class="data-table-header">
            <div class="data-table-header-start">
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
            <div class="data-table-header-end">
              <div class="kt-btn-group">
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

          <!-- Content -->
          {#if trafficLoading && trafficLogs.length === 0}
            <div class="data-table-loading">
              <LoadingSpinner size="lg" />
            </div>
          {:else if trafficLogs.length === 0}
            <div class="data-table-empty">
              <EmptyState
                icon="activity"
                title="No traffic logs"
                description={trafficSearch ? 'No results match your search' : 'Traffic will appear when VPN clients connect'}
              />
            </div>
          {:else}
            <div class="data-table-content">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Proto</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Country</th>
                  </tr>
                </thead>
                <tbody>
                  {#each trafficLogs as log}
                    {@const geo = geoData[log.dest_ip]}
                    {@const country = geo?.country_code || log.country}
                    <tr>
                      <td class="data-table-cell-nowrap">
                        <div class="flex items-center gap-1.5">
                          <Icon name="clock" size={14} class="text-muted-foreground" />
                          <div>
                            <div class="text-xs font-medium">{formatRelativeDate(log.timestamp)}</div>
                            <div class="text-[10px] text-muted-foreground">{formatTime(log.timestamp)}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <Badge variant={log.protocol === 'tcp' ? 'info' : 'warning'} size="sm">
                          {log.protocol?.toUpperCase()}
                        </Badge>
                      </td>
                      <td class="data-table-cell-mono">
                        <div class="flex items-center gap-2">
                          <Icon name="device-laptop" size={14} class="text-primary" />
                          {log.src_ip}
                        </div>
                      </td>
                      <td class="data-table-cell-mono">
                        <div class="flex items-center gap-2">
                          <Icon name="server" size={14} class="text-muted-foreground" />
                          {log.dest_ip}<span class="text-muted-foreground">:{log.dest_port}</span>
                        </div>
                      </td>
                      <td class="text-right">
                        {#if country}
                          <div class="flex items-center justify-end gap-2">
                            <CountryFlag code={country} />
                            <div class="hidden sm:flex items-center gap-2">
                              <div class="border-l border-dashed border-border h-6"></div>
                              <div class="text-right">
                                <div class="text-[11px] text-foreground">{geo?.country_name || country}</div>
                                {#if geo?.extra?.city || geo?.extra?.region}
                                  <div class="text-[10px] text-muted-foreground">{geo?.extra?.city}{geo?.extra?.city && geo?.extra?.region ? ', ' : ''}{geo?.extra?.region}</div>
                                {/if}
                              </div>
                            </div>
                          </div>
                        {:else}
                          <span class="text-muted-foreground">—</span>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>

            <!-- Footer -->
            <div class="data-table-footer">
              <Pagination
                bind:page={trafficPage}
                bind:perPage={trafficPerPage}
                total={trafficTotal}
                onPageChange={loadTrafficData}
              />
            </div>
          {/if}
        </div>

      <!-- Traefik Tab -->
      {:else if activeTab === 'traefik'}
        <div class="data-table">
          <!-- Header -->
          <div class="data-table-header">
            <div class="data-table-header-start">
              <Input
                type="search"
                bind:value={traefikSearch}
                placeholder="Search path, IP, method..."
                prefixIcon="search"
                class="sm:w-64"
              />
            </div>
            <div class="data-table-header-end">
              <Button variant="outline" size="sm" icon="refresh" onclick={loadTraefikLogs}>
                Refresh
              </Button>
            </div>
          </div>

          <!-- Content -->
          {#if traefikLoading && traefikLogs.length === 0}
            <div class="data-table-loading">
              <LoadingSpinner size="lg" />
            </div>
          {:else if filteredTraefikLogs.length === 0}
            <div class="data-table-empty">
              <EmptyState
                icon="file-text"
                title="No Logs Yet"
                description={traefikSearch ? 'No results match your search' : 'Access logs will appear when requests are made'}
              />
            </div>
          {:else}
            <div class="data-table-content">
              <table>
                <thead>
                  <tr>
                    <th>Time / Client</th>
                    <th>Request</th>
                    <th>Path</th>
                    <th>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {#each filteredTraefikLogs as log}
                    <tr>
                      <td class="data-table-cell-nowrap">
                        <div class="flex items-center gap-1.5">
                          <Icon name="clock" size={14} class="text-muted-foreground" />
                          <div>
                            <div class="text-xs font-medium">{formatRelativeDate(log.time)}, {formatTime(log.time)}</div>
                            <div class="text-[10px] text-muted-foreground font-mono">{log.clientIP}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <div class="flex items-center gap-1">
                          <Badge variant={log.method === 'GET' ? 'info' : log.method === 'POST' ? 'success' : 'muted'} size="sm">
                            {log.method}
                          </Badge>
                          <Icon name="arrow-right" size={12} class="text-muted-foreground" />
                          <Badge variant={log.status < 300 ? 'success' : log.status < 400 ? 'info' : 'danger'} size="sm">
                            {log.status}
                          </Badge>
                        </div>
                      </td>
                      <td class="data-table-cell-mono">{log.path}</td>
                      <td class="text-muted-foreground">{formatDuration(log.duration)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>

      <!-- AdGuard Tab -->
      {:else if activeTab === 'adguard'}
        <div class="data-table">
          <!-- Header -->
          <div class="data-table-header">
            <div class="data-table-header-start">
              <Input
                type="search"
                bind:value={adguardSearch}
                placeholder="Search domains, clients..."
                prefixIcon="search"
                class="sm:w-64"
              />
            </div>
            <div class="data-table-header-end">
              <Button variant="outline" size="sm" icon="refresh" onclick={loadAdGuardLogs}>
                Refresh
              </Button>
            </div>
          </div>

          <!-- Content -->
          {#if adguardLoading && adguardLogs.length === 0}
            <div class="data-table-loading">
              <LoadingSpinner size="lg" />
            </div>
          {:else if filteredAdGuardLogs.length === 0}
            <div class="data-table-empty">
              <EmptyState
                icon="list"
                title="No DNS Queries"
                description={adguardSearch ? 'No results match your search' : 'Waiting for VPN clients to make DNS requests...'}
              />
            </div>
          {:else}
            <div class="data-table-content">
              <table>
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
                      <td class="data-table-cell-nowrap">
                        <div class="flex items-center gap-1.5">
                          <Icon name="clock" size={14} class="text-muted-foreground" />
                          <div>
                            <div class="text-xs font-medium">{formatRelativeDate(log.time)}</div>
                            <div class="text-[10px] text-muted-foreground">{formatTime(log.time)}</div>
                          </div>
                        </div>
                      </td>
                      <td class="data-table-cell-mono data-table-cell-muted">{log.client || '-'}</td>
                      <td class="data-table-cell-mono {status.variant === 'danger' ? 'text-destructive' : ''}">{log.question?.name || '-'}</td>
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
