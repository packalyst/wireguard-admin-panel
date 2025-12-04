<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet } from '../stores/app.js'
  import { formatTime, formatRelativeDate } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Pagination from '../components/Pagination.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'

  let { loading = $bindable(true) } = $props()

  // Data
  let logs = $state([])
  let total = $state(0)
  let clients = $state([])

  // Load saved state from localStorage
  const savedState = typeof localStorage !== 'undefined'
    ? JSON.parse(localStorage.getItem('traffic') || '{}')
    : {}

  // Pagination & filters
  let page = $state(savedState.page || 1)
  let perPage = $state(savedState.perPage || parseInt(localStorage.getItem('settings_items_per_page') || '25'))
  let search = $state(savedState.search || '')
  let clientFilter = $state(savedState.client || '')

  // Auto-refresh
  let autoRefresh = $state(false)
  let refreshInterval = null

  // Derived
  const offset = $derived((page - 1) * perPage)

  // Save state to localStorage
  $effect(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('traffic', JSON.stringify({
        page,
        perPage,
        search,
        client: clientFilter
      }))
    }
  })

  // Debounce search
  let searchTimeout = null
  let searchQuery = $state(search)

  function handleSearchInput(e) {
    searchQuery = e.target.value
    clearTimeout(searchTimeout)
    searchTimeout = setTimeout(() => {
      search = searchQuery
      page = 1
      loadData()
    }, 400)
  }

  async function loadData() {
    try {
      const params = new URLSearchParams({
        limit: perPage.toString(),
        offset: offset.toString()
      })
      if (search) params.set('search', search)
      if (clientFilter) params.set('client', clientFilter)

      const res = await apiGet(`/api/fw/traffic?${params}`)
      logs = res.logs || []
      total = res.total || 0
      clients = res.clients || []
    } catch (e) {
      toast('Failed to load traffic: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  function formatLogTime(dateStr) {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  function formatLogDate(dateStr) {
    if (!dateStr) return '-'
    const date = new Date(dateStr)
    const today = new Date()
    if (date.toDateString() === today.toDateString()) return 'Today'
    const yesterday = new Date(today)
    yesterday.setDate(yesterday.getDate() - 1)
    if (date.toDateString() === yesterday.toDateString()) return 'Yesterday'
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' })
  }

  function setClientFilter(client) {
    clientFilter = client
    page = 1
    loadData()
  }

  function clearFilters() {
    search = ''
    searchQuery = ''
    clientFilter = ''
    page = 1
    loadData()
  }

  function toggleAutoRefresh() {
    autoRefresh = !autoRefresh
    if (autoRefresh) {
      refreshInterval = setInterval(loadData, 10000)
      toast('Auto-refresh enabled (10s)', 'info')
    } else {
      if (refreshInterval) clearInterval(refreshInterval)
      refreshInterval = null
    }
  }

  onMount(loadData)

  onDestroy(() => {
    if (refreshInterval) clearInterval(refreshInterval)
    if (searchTimeout) clearTimeout(searchTimeout)
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="activity"
    title="Traffic Logs"
    description="Monitor network traffic passing through the VPN. Track connections by source, destination, and protocol."
  />

  <!-- Toolbar -->
  <div class="rounded-xl border border-border bg-muted/50 px-4 py-3">
    <div class="flex flex-wrap items-center gap-3">
      <!-- Search -->
      <Input
        type="search"
        value={searchQuery}
        oninput={handleSearchInput}
        placeholder="Search IP, domain, port..."
        prefixIcon="search"
        class="min-w-[160px] flex-1 sm:flex-none sm:w-64"
      />

      <!-- Client filter -->
      {#if clients.length > 0}
        <select
          value={clientFilter}
          onchange={(e) => setClientFilter(e.target.value)}
          class="kt-input w-full sm:w-auto sm:min-w-[150px]"
        >
          <option value="">All clients</option>
          {#each clients as client}
            <option value={client}>{client}</option>
          {/each}
        </select>
      {/if}

      <!-- Clear filters -->
      {#if search || clientFilter}
        <span
          onclick={clearFilters}
          class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
        >
          <Icon name="x" size={14} />
          Clear
        </span>
      {/if}

      <div class="ml-auto"></div>

      <!-- Auto refresh -->
      <span
        onclick={toggleAutoRefresh}
        class="kt-badge kt-badge-outline {autoRefresh ? 'kt-badge-success' : 'kt-badge-secondary'} cursor-pointer"
      >
        <Icon name="refresh" size={14} class={autoRefresh ? 'animate-spin' : ''} />
        Auto
      </span>

      <!-- Refresh -->
      <span
        onclick={loadData}
        class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
      >
        <Icon name="refresh" size={14} />
        Refresh
      </span>
    </div>
  </div>

  <!-- Table -->
  {#if logs.length > 0}
    <div class="kt-table-wrapper rounded-xl border border-border bg-card overflow-hidden">
      <table class="kt-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th class="text-right">Port</th>
            <th class="text-center">Proto</th>
          </tr>
        </thead>
        <tbody>
          {#each logs as log}
            <tr>
              <td class="whitespace-nowrap">
                <div class="text-sm tabular-nums">{formatLogTime(log.timestamp)}</div>
                <div class="text-xs text-muted-foreground">{formatLogDate(log.timestamp)}</div>
              </td>
              <td>
                <button
                  onclick={() => setClientFilter(log.clientIP)}
                  class="inline-flex items-center gap-1.5 text-sm font-mono hover:text-primary transition-colors"
                >
                  <span class="w-2 h-2 rounded-full bg-success"></span>
                  {log.clientIP}
                </button>
              </td>
              <td>
                <div class="text-sm font-mono">{log.destIP}</div>
                {#if log.domain}
                  <div class="text-xs text-muted-foreground truncate max-w-[240px]" title={log.domain}>{log.domain}</div>
                {/if}
              </td>
              <td class="text-right">
                <span class="text-sm font-mono text-muted-foreground">{log.destPort || '—'}</span>
              </td>
              <td class="text-center">
                <span class="inline-flex items-center justify-center min-w-[42px] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide rounded-md
                  {log.protocol === 'tcp' ? 'bg-info/10 text-info' :
                   log.protocol === 'udp' ? 'bg-primary/10 text-primary' :
                   'bg-muted text-muted-foreground'}">
                  {log.protocol || '—'}
                </span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>

      <Pagination
        bind:page
        bind:perPage
        {total}
        onPageChange={loadData}
        onPerPageChange={loadData}
      />
    </div>
  {:else if !loading}
    <EmptyState
      icon="activity"
      title="No traffic logs"
      description={search || clientFilter ? 'No results match your filters' : 'Traffic will appear here when logged by the firewall'}
    />
    {#if search || clientFilter}
      <div class="flex justify-center">
        <Button onclick={clearFilters} variant="secondary" size="sm" icon="x">
          Clear filters
        </Button>
      </div>
    {/if}
  {/if}
</div>
