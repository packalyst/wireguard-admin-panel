<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiDelete } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import Pagination from '../components/Pagination.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'

  let { loading = $bindable(true) } = $props()

  // Data state
  let status = $state(null)
  let ports = $state([])
  let jails = $state([])
  let loadingPorts = $state(false)
  let loadingJails = $state(false)

  // Blocked IPs state (server-side pagination)
  let blockedIPs = $state([])
  let blockedTotal = $state(0)
  let blockedJails = $state([])
  let loadingBlocked = $state(false)

  // Attempts state (server-side pagination)
  let attempts = $state([])
  let attemptsTotal = $state(0)
  let attemptsJails = $state([])
  let loadingAttempts = $state(false)

  // Load saved state from localStorage
  const savedBlockedState = typeof localStorage !== 'undefined'
    ? JSON.parse(localStorage.getItem('firewall_blocked') || '{}')
    : {}
  const savedAttemptsState = typeof localStorage !== 'undefined'
    ? JSON.parse(localStorage.getItem('firewall_attempts') || '{}')
    : {}

  // UI state
  let activeTab = $state('ports')

  // Blocked tab state
  let blockedPage = $state(savedBlockedState.page || 1)
  let blockedPerPage = $state(savedBlockedState.perPage || parseInt(localStorage.getItem('settings_items_per_page') || '25'))
  let blockedSearch = $state(savedBlockedState.search || '')
  let blockedJailFilter = $state(savedBlockedState.jail || '')

  // Attempts tab state
  let attemptsPage = $state(savedAttemptsState.page || 1)
  let attemptsPerPage = $state(savedAttemptsState.perPage || parseInt(localStorage.getItem('settings_items_per_page') || '25'))
  let attemptsSearch = $state(savedAttemptsState.search || '')
  let attemptsJailFilter = $state(savedAttemptsState.jail || '')

  // Debounce for search
  let blockedSearchTimeout = null
  let blockedSearchQuery = $state(blockedSearch)
  let attemptsSearchTimeout = null
  let attemptsSearchQuery = $state(attemptsSearch)

  // Derived - offsets for API calls
  const blockedOffset = $derived((blockedPage - 1) * blockedPerPage)
  const attemptsOffset = $derived((attemptsPage - 1) * attemptsPerPage)

  // Save state to localStorage
  $effect(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('firewall_blocked', JSON.stringify({
        page: blockedPage,
        perPage: blockedPerPage,
        search: blockedSearch,
        jail: blockedJailFilter
      }))
    }
  })

  $effect(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('firewall_attempts', JSON.stringify({
        page: attemptsPage,
        perPage: attemptsPerPage,
        search: attemptsSearch,
        jail: attemptsJailFilter
      }))
    }
  })

  // Modals
  let showBlockModal = $state(false)
  let showUnblockModal = $state(false)
  let unblockingIP = $state(null)

  // Forms
  let newPort = $state('')
  let blockForm = $state({ ip: '', reason: '', duration: '30d' })

  // Load status on mount
  async function loadStatus() {
    try {
      status = await apiGet('/api/fw/status')
    } catch (e) {
      console.error('Failed to load status:', e)
    } finally {
      loading = false
    }
  }

  // Load data for each tab on demand
  async function loadPorts() {
    if (ports.length > 0) return
    loadingPorts = true
    try {
      const res = await apiGet('/api/fw/ports')
      ports = res.ports || res || []
    } catch (e) {
      toast('Failed to load ports: ' + e.message, 'error')
    } finally {
      loadingPorts = false
    }
  }

  async function loadBlocked() {
    loadingBlocked = true
    try {
      const params = new URLSearchParams({
        limit: blockedPerPage.toString(),
        offset: blockedOffset.toString()
      })
      if (blockedSearch) params.set('search', blockedSearch)
      if (blockedJailFilter) params.set('jail', blockedJailFilter)

      const res = await apiGet(`/api/fw/blocked?${params}`)
      blockedIPs = res.blocked || []
      blockedTotal = res.total || 0
      blockedJails = res.jails || []
    } catch (e) {
      toast('Failed to load blocked IPs: ' + e.message, 'error')
    } finally {
      loadingBlocked = false
    }
  }

  async function loadAttempts() {
    loadingAttempts = true
    try {
      const params = new URLSearchParams({
        limit: attemptsPerPage.toString(),
        offset: attemptsOffset.toString()
      })
      if (attemptsSearch) params.set('search', attemptsSearch)
      if (attemptsJailFilter) params.set('jail', attemptsJailFilter)

      const res = await apiGet(`/api/fw/attempts?${params}`)
      attempts = res.attempts || []
      attemptsTotal = res.total || 0
      attemptsJails = res.jails || []
    } catch (e) {
      toast('Failed to load attempts: ' + e.message, 'error')
    } finally {
      loadingAttempts = false
    }
  }

  // Debounced search handlers
  function handleBlockedSearchInput(e) {
    blockedSearchQuery = e.target.value
    clearTimeout(blockedSearchTimeout)
    blockedSearchTimeout = setTimeout(() => {
      blockedSearch = blockedSearchQuery
      blockedPage = 1
      loadBlocked()
    }, 400)
  }

  function handleAttemptsSearchInput(e) {
    attemptsSearchQuery = e.target.value
    clearTimeout(attemptsSearchTimeout)
    attemptsSearchTimeout = setTimeout(() => {
      attemptsSearch = attemptsSearchQuery
      attemptsPage = 1
      loadAttempts()
    }, 400)
  }

  function setBlockedJailFilter(jail) {
    blockedJailFilter = jail
    blockedPage = 1
    loadBlocked()
  }

  function setAttemptsJailFilter(jail) {
    attemptsJailFilter = jail
    attemptsPage = 1
    loadAttempts()
  }

  function clearBlockedFilters() {
    blockedSearch = ''
    blockedSearchQuery = ''
    blockedJailFilter = ''
    blockedPage = 1
    loadBlocked()
  }

  function clearAttemptsFilters() {
    attemptsSearch = ''
    attemptsSearchQuery = ''
    attemptsJailFilter = ''
    attemptsPage = 1
    loadAttempts()
  }

  async function loadJails() {
    if (jails.length > 0) return
    loadingJails = true
    try {
      const res = await apiGet('/api/fw/jails')
      jails = res.jails || res || []
    } catch (e) {
      toast('Failed to load jails: ' + e.message, 'error')
    } finally {
      loadingJails = false
    }
  }

  // Reload specific section
  async function reloadSection(section) {
    if (section === 'ports') {
      ports = []
      await loadPorts()
    } else if (section === 'blocked') {
      await loadBlocked()
      await loadStatus()
    } else if (section === 'attempts') {
      await loadAttempts()
    } else if (section === 'jails') {
      jails = []
      await loadJails()
    }
  }

  // Tab change handler
  function switchTab(tab) {
    activeTab = tab
    if (tab === 'ports') loadPorts()
    else if (tab === 'blocked') loadBlocked()
    else if (tab === 'attempts') loadAttempts()
    else if (tab === 'jails') loadJails()
  }

  // Sorted ports (avoid mutation in template)
  const sortedPorts = $derived([...ports].sort((a, b) => a.port - b.port))

  // Actions
  async function addPort() {
    const port = parseInt(newPort)
    if (!port || port < 1 || port > 65535) {
      toast('Invalid port number', 'error')
      return
    }
    try {
      await apiPost('/api/fw/ports', { port, protocol: 'tcp' })
      toast(`Port ${port} added`, 'success')
      newPort = ''
      await reloadSection('ports')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function removePort(port, protocol = 'tcp') {
    try {
      await apiDelete(`/api/fw/ports/${port}?protocol=${protocol}`)
      toast(`Port ${port} removed`, 'success')
      await reloadSection('ports')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function blockIP() {
    if (!blockForm.ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      toast('Invalid IP address', 'error')
      return
    }
    let banTime = 0
    if (blockForm.duration !== 'permanent') {
      const match = blockForm.duration.match(/^(\d+)([hdm])$/)
      if (match) {
        const val = parseInt(match[1])
        const unit = match[2]
        if (unit === 'h') banTime = val * 3600
        else if (unit === 'd') banTime = val * 86400
        else if (unit === 'm') banTime = val * 60
      }
    }
    try {
      await apiPost('/api/fw/blocked', {
        ip: blockForm.ip,
        reason: blockForm.reason || 'Manual block',
        banTime
      })
      toast(`IP ${blockForm.ip} blocked`, 'success')
      showBlockModal = false
      blockForm = { ip: '', reason: '', duration: '30d' }
      await reloadSection('blocked')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function confirmUnblock(blocked) {
    unblockingIP = blocked
    showUnblockModal = true
  }

  async function unblockIP() {
    if (!unblockingIP) return
    try {
      const url = unblockingIP.jailName
        ? `/api/fw/blocked/${unblockingIP.ip}?jail=${unblockingIP.jailName}`
        : `/api/fw/blocked/${unblockingIP.ip}`
      await apiDelete(url)
      toast(`IP ${unblockingIP.ip} unblocked`, 'success')
      showUnblockModal = false
      unblockingIP = null
      await reloadSection('blocked')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Helpers
  function timeAgo(dateStr) {
    if (!dateStr) return 'Never'
    const date = new Date(dateStr)
    const now = new Date()
    const diff = Math.floor((now - date) / 1000)

    if (diff < 60) return 'just now'
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`
    return date.toLocaleDateString()
  }

  function formatTimeRemaining(expiresAt) {
    if (!expiresAt) return 'Permanent'
    const expires = new Date(expiresAt)
    const now = new Date()
    const diff = expires - now

    if (diff <= 0) return 'Expired'

    const hours = Math.floor(diff / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))

    if (hours > 24) {
      const days = Math.floor(hours / 24)
      return `${days}d ${hours % 24}h`
    }
    if (hours > 0) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }

  function formatBanTime(seconds) {
    if (!seconds) return '-'
    if (seconds < 0) return 'Permanent'
    if (seconds < 60) return `${seconds}s`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
    return `${Math.floor(seconds / 86400)}d`
  }

  onMount(() => {
    loadStatus()
    loadPorts() // Load ports by default
  })

  onDestroy(() => {
    if (blockedSearchTimeout) clearTimeout(blockedSearchTimeout)
    if (attemptsSearchTimeout) clearTimeout(attemptsSearchTimeout)
  })
</script>

{#if loading}
  <div class="flex flex-col items-center justify-center py-12">
    <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    <p class="mt-3 text-sm text-muted-foreground">Loading firewall...</p>
  </div>
{:else}
  <div class="space-y-4">
    <!-- Status Card -->
    <div class="bg-card border border-border rounded-xl p-4">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-xl flex items-center justify-center {status?.enabled ? 'bg-success/15 text-success' : 'bg-muted text-muted-foreground'}">
          <Icon name="shield" size={24} />
        </div>
        <div class="flex-1">
          <div class="text-base font-semibold text-foreground">
            {status?.enabled ? 'Firewall Active' : 'Firewall Inactive'}
          </div>
          <div class="text-sm text-muted-foreground">
            Policy: {status?.defaultPolicy || 'drop'}
          </div>
        </div>
        <div class="flex items-center gap-6">
          <div class="flex items-center gap-2 text-sm text-muted-foreground">
            <Icon name="ban" size={16} />
            <span><strong class="text-foreground">{status?.blockedIPCount || 0}</strong> blocked</span>
          </div>
          <div class="flex items-center gap-2 text-sm text-muted-foreground">
            <Icon name="lock" size={16} />
            <span><strong class="text-foreground">{status?.activeJails || 0}</strong> jails</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Tabs Card -->
    <div class="bg-card border border-border rounded-xl overflow-hidden">
      <!-- Tab buttons -->
      <div class="flex border-b border-border">
        <button
          onclick={() => switchTab('ports')}
          class="px-5 py-3 text-sm font-medium transition-colors relative {activeTab === 'ports' ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}"
        >
          Ports
          {#if activeTab === 'ports'}
            <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"></div>
          {/if}
        </button>
        <button
          onclick={() => switchTab('blocked')}
          class="px-5 py-3 text-sm font-medium transition-colors relative {activeTab === 'blocked' ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}"
        >
          Blocked
          {#if (status?.blockedIPCount || 0) > 0}
            <span class="ml-1.5 px-1.5 py-0.5 text-xs bg-destructive/15 text-destructive rounded-full">
              {status?.blockedIPCount}
            </span>
          {/if}
          {#if activeTab === 'blocked'}
            <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"></div>
          {/if}
        </button>
        <button
          onclick={() => switchTab('attempts')}
          class="px-5 py-3 text-sm font-medium transition-colors relative {activeTab === 'attempts' ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}"
        >
          Activity
          {#if activeTab === 'attempts'}
            <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"></div>
          {/if}
        </button>
        <button
          onclick={() => switchTab('jails')}
          class="px-5 py-3 text-sm font-medium transition-colors relative {activeTab === 'jails' ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}"
        >
          Jails
          {#if activeTab === 'jails'}
            <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"></div>
          {/if}
        </button>
      </div>

      <!-- Tab Content -->
      <div class="p-5">
        <!-- Ports Tab -->
        {#if activeTab === 'ports'}
          <!-- Add Port Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 mb-4 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-wrap items-center gap-3">
              <Input
                type="number"
                bind:value={newPort}
                placeholder="Port number"
                class="w-32"
                min="1"
                max="65535"
                onkeydown={(e) => e.key === 'Enter' && addPort()}
              />
              <Button onclick={addPort} size="sm" icon="plus">
                Add Port
              </Button>
              <div class="ml-auto text-sm text-slate-500 dark:text-zinc-400">
                {sortedPorts.length} ports allowed
              </div>
            </div>
          </div>

          {#if loadingPorts}
            <div class="flex flex-col items-center justify-center py-8">
              <div class="w-6 h-6 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              <p class="mt-2 text-sm text-muted-foreground">Loading ports...</p>
            </div>
          {:else if sortedPorts.length > 0}
            <div class="rounded-xl border border-slate-200 bg-white overflow-hidden dark:border-zinc-800 dark:bg-zinc-900">
              <div class="overflow-x-auto">
                <table class="w-full">
                  <thead>
                    <tr class="border-b border-slate-200 dark:border-zinc-700">
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Port</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Protocol</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Type</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Service</th>
                      <th class="px-4 py-3 w-10"></th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-100 dark:divide-zinc-800">
                    {#each sortedPorts as p}
                      <tr class="group hover:bg-slate-50 dark:hover:bg-zinc-800/50 transition-colors">
                        <td class="px-4 py-3 align-middle">
                          <code class="text-sm font-mono font-semibold text-slate-900 dark:text-zinc-100">{p.port}</code>
                        </td>
                        <td class="px-4 py-3 align-middle">
                          <span class="inline-flex items-center justify-center min-w-[42px] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide rounded-md bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
                            {p.protocol || 'tcp'}
                          </span>
                        </td>
                        <td class="px-4 py-3 align-middle">
                          {#if p.essential}
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-md bg-amber-50 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400">
                              <Icon name="shield-check" size={12} />
                              Essential
                            </span>
                          {:else}
                            <span class="text-xs text-slate-500 dark:text-zinc-500">Custom</span>
                          {/if}
                        </td>
                        <td class="px-4 py-3 align-middle text-sm text-slate-600 dark:text-zinc-400">
                          {#if p.service}
                            {p.service}
                          {:else if p.port === 22}SSH
                          {:else if p.port === 80}HTTP
                          {:else if p.port === 443}HTTPS
                          {:else if p.port === 51820}WireGuard
                          {:else if p.port === 8080}API
                          {:else if p.port === 8081}Admin API
                          {:else if p.port === 8082}Traefik
                          {:else if p.port === 8083}AdGuard
                          {:else if p.port === 3478}STUN
                          {:else}—
                          {/if}
                        </td>
                        <td class="px-4 py-3 align-middle">
                          {#if !p.essential}
                            <button
                              onclick={() => removePort(p.port, p.protocol)}
                              class="p-1.5 rounded text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                              title="Remove port"
                            >
                              <Icon name="trash" size={14} />
                            </button>
                          {:else}
                            <span class="p-1.5 text-slate-300 dark:text-zinc-600">
                              <Icon name="lock" size={14} />
                            </span>
                          {/if}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            </div>
          {:else}
            <div class="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-slate-50 py-16 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-300">
                <Icon name="shield" size={24} />
              </div>
              <h4 class="mt-4 text-base font-medium text-slate-700 dark:text-zinc-200">No ports configured</h4>
              <p class="mt-1 text-sm text-slate-500 dark:text-zinc-400">Add ports to allow traffic through the firewall</p>
            </div>
          {/if}

        <!-- Blocked Tab -->
        {:else if activeTab === 'blocked'}
          <!-- Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 mb-4 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-wrap items-center gap-3">
              <!-- Search -->
              <Input
                type="search"
                value={blockedSearchQuery}
                oninput={handleBlockedSearchInput}
                placeholder="Search IP, reason..."
                prefixIcon="search"
                class="min-w-[160px] flex-1 sm:flex-none sm:w-64"
              />

              <!-- Jail filter -->
              {#if blockedJails.length > 0}
                <select
                  value={blockedJailFilter}
                  onchange={(e) => setBlockedJailFilter(e.target.value)}
                  class="kt-input w-full sm:w-auto sm:min-w-[140px]"
                >
                  <option value="">All jails</option>
                  {#each blockedJails as jail}
                    <option value={jail}>{jail}</option>
                  {/each}
                </select>
              {/if}

              <!-- Clear filters -->
              {#if blockedSearch || blockedJailFilter}
                <span
                  onclick={clearBlockedFilters}
                  class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
                  role="button"
                  tabindex="0"
                  onkeydown={(e) => e.key === 'Enter' && clearBlockedFilters()}
                >
                  <Icon name="x" size={14} />
                  Clear
                </span>
              {/if}

              <div class="ml-auto"></div>

              <Button onclick={() => showBlockModal = true} size="sm" icon="plus">
                Block IP
              </Button>
            </div>
          </div>

          {#if blockedIPs.length > 0}
            <div class="rounded-xl border border-slate-200 bg-white overflow-hidden dark:border-zinc-800 dark:bg-zinc-900">
              <div class="overflow-x-auto">
                <table class="w-full">
                  <thead>
                    <tr class="border-b border-slate-200 dark:border-zinc-700">
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">IP Address</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Jail</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Reason</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Blocked</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Expires</th>
                      <th class="px-4 py-3 w-10"></th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-100 dark:divide-zinc-800">
                    {#each blockedIPs as blocked}
                      <tr class="group hover:bg-slate-50 dark:hover:bg-zinc-800/50 transition-colors">
                        <td class="px-4 py-3 align-top">
                          <code class="text-sm font-mono text-slate-900 dark:text-zinc-100">{blocked.ip}</code>
                        </td>
                        <td class="px-4 py-3 align-top">
                          <button
                            onclick={() => setBlockedJailFilter(blocked.jailName)}
                            class="inline-flex"
                          >
                            <Badge
                              variant={blocked.manual ? 'info' : blocked.jailName === 'sshd' ? 'danger' : 'warning'}
                              size="sm"
                            >
                              {blocked.jailName || 'manual'}
                            </Badge>
                          </button>
                        </td>
                        <td class="px-4 py-3 align-top text-sm text-slate-600 dark:text-zinc-400 max-w-48 truncate" title={blocked.reason}>
                          {blocked.reason || '-'}
                        </td>
                        <td class="px-4 py-3 align-top whitespace-nowrap">
                          <div class="text-sm text-slate-600 dark:text-zinc-400">{timeAgo(blocked.blockedAt)}</div>
                        </td>
                        <td class="px-4 py-3 align-top whitespace-nowrap">
                          {#if blocked.expiresAt}
                            <span class="text-sm text-warning font-medium">{formatTimeRemaining(blocked.expiresAt)}</span>
                          {:else}
                            <span class="text-xs text-destructive uppercase font-semibold">Permanent</span>
                          {/if}
                        </td>
                        <td class="px-4 py-3 align-top">
                          <button
                            onclick={() => confirmUnblock(blocked)}
                            class="p-1.5 rounded text-muted-foreground hover:text-success hover:bg-success/10 transition-colors"
                            title="Unblock"
                          >
                            <Icon name="lock-open" size={14} />
                          </button>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>

              <Pagination
                bind:page={blockedPage}
                bind:perPage={blockedPerPage}
                total={blockedTotal}
                onPageChange={loadBlocked}
                onPerPageChange={loadBlocked}
              />
            </div>
          {:else if !loadingBlocked}
            <div class="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-slate-50 py-16 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-12 w-12 items-center justify-center rounded-full bg-success/10 text-success">
                <Icon name="shield-check" size={24} />
              </div>
              <h4 class="mt-4 text-base font-medium text-slate-700 dark:text-zinc-200">No blocked IPs</h4>
              <p class="mt-1 text-sm text-slate-500 dark:text-zinc-400">
                {#if blockedSearch || blockedJailFilter}
                  No results match your filters
                {:else}
                  IPs will appear here when blocked by the firewall
                {/if}
              </p>
              {#if blockedSearch || blockedJailFilter}
                <Button onclick={clearBlockedFilters} variant="secondary" size="sm" icon="x" class="mt-4">
                  Clear filters
                </Button>
              {/if}
            </div>
          {/if}

        <!-- Activity Tab -->
        {:else if activeTab === 'attempts'}
          <!-- Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 mb-4 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-wrap items-center gap-3">
              <!-- Search -->
              <Input
                type="search"
                value={attemptsSearchQuery}
                oninput={handleAttemptsSearchInput}
                placeholder="Search IP, port..."
                prefixIcon="search"
                class="min-w-[160px] flex-1 sm:flex-none sm:w-64"
              />

              <!-- Jail filter -->
              {#if attemptsJails.length > 0}
                <select
                  value={attemptsJailFilter}
                  onchange={(e) => setAttemptsJailFilter(e.target.value)}
                  class="kt-input w-full sm:w-auto sm:min-w-[140px]"
                >
                  <option value="">All jails</option>
                  {#each attemptsJails as jail}
                    <option value={jail}>{jail}</option>
                  {/each}
                </select>
              {/if}

              <!-- Clear filters -->
              {#if attemptsSearch || attemptsJailFilter}
                <span
                  onclick={clearAttemptsFilters}
                  class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
                  role="button"
                  tabindex="0"
                  onkeydown={(e) => e.key === 'Enter' && clearAttemptsFilters()}
                >
                  <Icon name="x" size={14} />
                  Clear
                </span>
              {/if}

              <div class="ml-auto"></div>

              <span
                onclick={() => loadAttempts()}
                class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
                role="button"
                tabindex="0"
                onkeydown={(e) => e.key === 'Enter' && loadAttempts()}
              >
                <Icon name="refresh" size={14} />
                Refresh
              </span>
            </div>
          </div>

          {#if attempts.length > 0}
            <div class="rounded-xl border border-slate-200 bg-white overflow-hidden dark:border-zinc-800 dark:bg-zinc-900">
              <div class="overflow-x-auto">
                <table class="w-full">
                  <thead>
                    <tr class="border-b border-slate-200 dark:border-zinc-700">
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Time</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Source IP</th>
                      <th class="px-4 py-3 text-right text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Port</th>
                      <th class="px-4 py-3 text-center text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Jail</th>
                      <th class="px-4 py-3 text-center text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Action</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-100 dark:divide-zinc-800">
                    {#each attempts as attempt}
                      <tr class="group hover:bg-slate-50 dark:hover:bg-zinc-800/50 transition-colors">
                        <td class="px-4 py-3 align-top whitespace-nowrap">
                          <div class="text-sm text-slate-600 dark:text-zinc-400">{timeAgo(attempt.timestamp)}</div>
                        </td>
                        <td class="px-4 py-3 align-top">
                          <code class="text-sm font-mono text-slate-900 dark:text-zinc-100">{attempt.sourceIP}</code>
                        </td>
                        <td class="px-4 py-3 align-top text-right">
                          <span class="text-sm font-mono text-slate-600 dark:text-zinc-400">{attempt.destPort || '—'}</span>
                        </td>
                        <td class="px-4 py-3 align-top text-center">
                          <button onclick={() => setAttemptsJailFilter(attempt.jailName)} class="inline-flex">
                            <Badge variant="warning" size="sm">{attempt.jailName || '-'}</Badge>
                          </button>
                        </td>
                        <td class="px-4 py-3 align-top text-center">
                          <Badge variant={attempt.action === 'blocked' ? 'danger' : 'success'} size="sm">
                            {attempt.action}
                          </Badge>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>

              <Pagination
                bind:page={attemptsPage}
                bind:perPage={attemptsPerPage}
                total={attemptsTotal}
                onPageChange={loadAttempts}
                onPerPageChange={loadAttempts}
              />
            </div>
          {:else if !loadingAttempts}
            <div class="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-slate-50 py-16 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-300">
                <Icon name="activity" size={24} />
              </div>
              <h4 class="mt-4 text-base font-medium text-slate-700 dark:text-zinc-200">No activity</h4>
              <p class="mt-1 text-sm text-slate-500 dark:text-zinc-400">
                {#if attemptsSearch || attemptsJailFilter}
                  No results match your filters
                {:else}
                  Connection attempts will appear here when logged
                {/if}
              </p>
              {#if attemptsSearch || attemptsJailFilter}
                <Button onclick={clearAttemptsFilters} variant="secondary" size="sm" icon="x" class="mt-4">
                  Clear filters
                </Button>
              {/if}
            </div>
          {/if}

        <!-- Jails Tab -->
        {:else if activeTab === 'jails'}
          {#if loadingJails}
            <div class="flex flex-col items-center justify-center py-8">
              <div class="w-6 h-6 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              <p class="mt-2 text-sm text-muted-foreground">Loading jails...</p>
            </div>
          {:else if jails.length === 0}
            <div class="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-slate-50 py-16 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
              <div class="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-300">
                <Icon name="lock" size={24} />
              </div>
              <h4 class="mt-4 text-base font-medium text-slate-700 dark:text-zinc-200">No Jails Configured</h4>
              <p class="mt-1 text-sm text-slate-500 dark:text-zinc-400">Security jails will appear here</p>
            </div>
          {:else}
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              {#each jails as jail}
                <div class="rounded-xl border border-slate-200 bg-white overflow-hidden dark:border-zinc-800 dark:bg-zinc-900 {!jail.enabled && 'opacity-60'}">
                  <!-- Header -->
                  <div class="flex items-center justify-between px-5 py-4 border-b border-slate-100 dark:border-zinc-800">
                    <div class="flex items-center gap-3">
                      <div class="flex h-10 w-10 items-center justify-center rounded-lg {jail.enabled ? 'bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400' : 'bg-slate-100 text-slate-400 dark:bg-zinc-800 dark:text-zinc-500'}">
                        <Icon name={jail.name === 'sshd' ? 'key' : 'shield'} size={20} />
                      </div>
                      <div>
                        <h3 class="font-semibold text-slate-900 dark:text-zinc-100 capitalize">{jail.name}</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-500">Port {jail.port || 'all'}</p>
                      </div>
                    </div>
                    <div class="flex items-center gap-2">
                      {#if jail.enabled}
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400">
                          <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                          Active
                        </span>
                      {:else}
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-500 dark:bg-zinc-800 dark:text-zinc-400">
                          Disabled
                        </span>
                      {/if}
                    </div>
                  </div>

                  <!-- Stats -->
                  <div class="grid grid-cols-2 divide-x divide-slate-100 dark:divide-zinc-800">
                    <div class="px-5 py-4 text-center">
                      <div class="text-2xl font-bold text-slate-900 dark:text-zinc-100">{jail.currentlyBanned || 0}</div>
                      <div class="text-xs text-slate-500 dark:text-zinc-500 mt-0.5">Currently Banned</div>
                    </div>
                    <div class="px-5 py-4 text-center">
                      <div class="text-2xl font-bold text-slate-900 dark:text-zinc-100">{jail.totalBanned || 0}</div>
                      <div class="text-xs text-slate-500 dark:text-zinc-500 mt-0.5">Total Banned</div>
                    </div>
                  </div>

                  <!-- Config -->
                  <div class="px-5 py-3 bg-slate-50 dark:bg-zinc-800/50 border-t border-slate-100 dark:border-zinc-800">
                    <div class="flex items-center justify-between text-xs">
                      <div class="flex items-center gap-4">
                        <div class="flex items-center gap-1.5">
                          <span class="text-slate-400 dark:text-zinc-500">Retry</span>
                          <span class="font-semibold text-slate-700 dark:text-zinc-300">{jail.maxRetry || 5}</span>
                        </div>
                        <div class="flex items-center gap-1.5">
                          <span class="text-slate-400 dark:text-zinc-500">Find</span>
                          <span class="font-semibold text-slate-700 dark:text-zinc-300">{formatBanTime(jail.findTime)}</span>
                        </div>
                        <div class="flex items-center gap-1.5">
                          <span class="text-slate-400 dark:text-zinc-500">Ban</span>
                          <span class="font-semibold text-slate-700 dark:text-zinc-300">{formatBanTime(jail.banTime)}</span>
                        </div>
                      </div>
                      <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide bg-slate-200 text-slate-600 dark:bg-zinc-700 dark:text-zinc-400">
                        {jail.action || 'drop'}
                      </span>
                    </div>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      </div>
    </div>
  </div>
{/if}

<!-- Block IP Modal -->
<Modal bind:open={showBlockModal} title="Block IP Address" size="sm">
  <form onsubmit={(e) => { e.preventDefault(); blockIP() }}>
    <div class="space-y-4">
      <Input
        label="IP Address"
        labelClass="block text-sm font-medium text-foreground mb-1.5"
        bind:value={blockForm.ip}
        class="w-full"
        placeholder="e.g. 192.168.1.100"
        required
      />
      <Input
        label="Reason"
        labelClass="block text-sm font-medium text-foreground mb-1.5"
        bind:value={blockForm.reason}
        class="w-full"
        placeholder="Manual block (optional)"
      />
      <div>
        <label class="block text-sm font-medium text-foreground mb-1.5">Duration</label>
        <select bind:value={blockForm.duration} class="kt-input w-full">
          <option value="1h">1 hour</option>
          <option value="24h">24 hours</option>
          <option value="7d">7 days</option>
          <option value="30d">30 days</option>
          <option value="90d">90 days</option>
          <option value="permanent">Permanent</option>
        </select>
      </div>
    </div>
    <div class="flex justify-end gap-2 mt-6">
      <Button type="button" onclick={() => showBlockModal = false} variant="secondary">
        Cancel
      </Button>
      <Button type="submit" variant="destructive" icon="ban">
        Block IP
      </Button>
    </div>
  </form>
</Modal>

<!-- Unblock Confirmation Modal -->
<Modal bind:open={showUnblockModal} title="Unblock IP" size="sm">
  {#if unblockingIP}
    <div class="text-center">
      <div class="w-12 h-12 rounded-full bg-success/10 flex items-center justify-center mx-auto mb-4">
        <Icon name="lock-open" size={24} class="text-success" />
      </div>
      <p class="text-foreground mb-2">
        Unblock <strong>{unblockingIP.ip}</strong>?
      </p>
      <p class="text-sm text-muted-foreground">
        This IP will be able to connect again.
      </p>
    </div>

    <div class="flex justify-end gap-2 mt-6">
      <Button
        type="button"
        onclick={() => { showUnblockModal = false; unblockingIP = null }}
        variant="secondary"
      >
        Cancel
      </Button>
      <Button
        type="button"
        onclick={unblockIP}
        icon="lock-open"
      >
        Unblock
      </Button>
    </div>
  {/if}
</Modal>
