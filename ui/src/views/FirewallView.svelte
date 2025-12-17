<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete } from '../stores/app.js'
  import { timeAgo } from '$lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import Pagination from '../components/Pagination.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Tabs from '../components/Tabs.svelte'

  let { loading = $bindable(true) } = $props()

  // Tabs with dynamic badge for blocked count
  const tabs = $derived([
    { id: 'ports', label: 'Ports', icon: 'lock' },
    { id: 'blocked', label: 'Blocked', icon: 'ban', badge: (status?.blockedIPCount || 0) > 0 ? status?.blockedIPCount : undefined },
    { id: 'attempts', label: 'Activity', icon: 'activity' },
    { id: 'jails', label: 'Jails', icon: 'shield' }
  ])

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
  let showSSHModal = $state(false)
  let showJailModal = $state(false)
  let showDeleteJailModal = $state(false)
  let unblockingIP = $state(null)
  let deletingJail = $state(null)

  // SSH port state
  let sshPort = $state(22)
  let newSSHPort = $state('')
  let changingSSH = $state(false)

  // Forms
  let newPort = $state('')
  let blockForm = $state({ ip: '', reason: '', duration: '30d' })
  let jailForm = $state({
    id: null,
    name: '',
    enabled: true,
    logFile: '/var/log/kern.log',
    filterRegex: '',
    maxRetry: 10,
    findTime: 3600,
    banTime: 2592000,
    port: 'all',
    action: 'drop',
    escalateEnabled: false,
    escalateThreshold: 3,
    escalateWindow: 3600
  })
  let savingJail = $state(false)

  // Blocklist import state
  let showImportModal = $state(false)
  let blocklists = $state([])
  let loadingBlocklists = $state(false)
  let importingSource = $state(null)
  let customURL = $state('')

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

  // Load SSH port
  async function loadSSHPort() {
    try {
      const res = await apiGet('/api/fw/ssh')
      sshPort = res.port || 22
    } catch (e) {
      console.error('Failed to load SSH port:', e)
    }
  }

  // Change SSH port
  async function changeSSHPort() {
    const port = parseInt(newSSHPort)
    if (!port || port < 1 || port > 65535) {
      toast('Invalid port number (1-65535)', 'error')
      return
    }
    if (port === sshPort) {
      toast('SSH is already on this port', 'info')
      return
    }

    changingSSH = true
    try {
      const res = await apiPost('/api/fw/ssh', { port })
      if (res.status === 'success') {
        toast(`SSH port changed from ${res.oldPort} to ${res.newPort}`, 'success')
        sshPort = res.newPort
        showSSHModal = false
        newSSHPort = ''
        // Reload ports to reflect the change
        ports = []
        await loadPorts()
      } else if (res.status === 'unchanged') {
        toast(res.message, 'info')
      }
    } catch (e) {
      toast('Failed to change SSH port: ' + e.message, 'error')
    } finally {
      changingSSH = false
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
  // Load data when tab changes (Tabs component handles the activeTab state)
  $effect(() => {
    if (activeTab === 'ports') loadPorts()
    else if (activeTab === 'blocked') loadBlocked()
    else if (activeTab === 'attempts') loadAttempts()
    else if (activeTab === 'jails') loadJails()
  })

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
    // Validate IP or CIDR (e.g., 192.168.1.100 or 192.168.1.0/24)
    const ipRegex = /^\d+\.\d+\.\d+\.\d+$/
    const cidrRegex = /^\d+\.\d+\.\d+\.\d+\/\d+$/
    if (!ipRegex.test(blockForm.ip) && !cidrRegex.test(blockForm.ip)) {
      toast('Invalid IP address or CIDR (e.g., 192.168.1.100 or 192.168.1.0/24)', 'error')
      return
    }
    // Validate CIDR prefix
    if (cidrRegex.test(blockForm.ip)) {
      const prefix = parseInt(blockForm.ip.split('/')[1])
      if (prefix < 8 || prefix > 32) {
        toast('CIDR prefix must be between /8 and /32', 'error')
        return
      }
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
      const res = await apiPost('/api/fw/blocked', {
        ip: blockForm.ip,
        reason: blockForm.reason || 'Manual block',
        banTime
      })
      const msg = res.isRange ? `Range ${res.ip} blocked` : `IP ${res.ip} blocked`
      toast(msg, 'success')
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

  // Jail management
  function openCreateJail() {
    jailForm = {
      id: null,
      name: '',
      enabled: true,
      logFile: '/var/log/kern.log',
      filterRegex: '',
      maxRetry: 10,
      findTime: 3600,
      banTime: 2592000,
      port: 'all',
      action: 'drop',
      escalateEnabled: false,
      escalateThreshold: 3,
      escalateWindow: 3600
    }
    showJailModal = true
  }

  function openEditJail(jail) {
    jailForm = {
      id: jail.id,
      name: jail.name,
      enabled: jail.enabled,
      logFile: jail.logFile,
      filterRegex: jail.filterRegex,
      maxRetry: jail.maxRetry,
      findTime: jail.findTime,
      banTime: jail.banTime,
      port: jail.port,
      action: jail.action,
      escalateEnabled: jail.escalateEnabled || false,
      escalateThreshold: jail.escalateThreshold || 3,
      escalateWindow: jail.escalateWindow || 3600
    }
    showJailModal = true
  }

  async function saveJail() {
    if (!jailForm.name.trim()) {
      toast('Jail name is required', 'error')
      return
    }
    if (!jailForm.filterRegex.trim()) {
      toast('Filter regex is required', 'error')
      return
    }

    savingJail = true
    try {
      const jailData = {
        enabled: jailForm.enabled,
        logFile: jailForm.logFile,
        filterRegex: jailForm.filterRegex,
        maxRetry: parseInt(jailForm.maxRetry) || 10,
        findTime: parseInt(jailForm.findTime) || 3600,
        banTime: parseInt(jailForm.banTime) || 2592000,
        port: jailForm.port,
        action: jailForm.action,
        escalateEnabled: jailForm.escalateEnabled,
        escalateThreshold: parseInt(jailForm.escalateThreshold) || 3,
        escalateWindow: parseInt(jailForm.escalateWindow) || 3600
      }

      if (jailForm.id) {
        // Update existing jail
        await apiPut(`/api/fw/jails/${jailForm.name}`, jailData)
        toast(`Jail "${jailForm.name}" updated`, 'success')
      } else {
        // Create new jail
        await apiPost('/api/fw/jails', { name: jailForm.name, ...jailData })
        toast(`Jail "${jailForm.name}" created`, 'success')
      }
      showJailModal = false
      await reloadSection('jails')
      await loadStatus()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      savingJail = false
    }
  }

  function confirmDeleteJail(jail) {
    deletingJail = jail
    showDeleteJailModal = true
  }

  async function deleteJail() {
    if (!deletingJail) return
    try {
      await apiDelete(`/api/fw/jails/${deletingJail.name}`)
      toast(`Jail "${deletingJail.name}" deleted`, 'success')
      showDeleteJailModal = false
      deletingJail = null
      await reloadSection('jails')
      await loadStatus()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Blocklist import
  async function openImportModal() {
    showImportModal = true
    if (blocklists.length === 0) {
      loadingBlocklists = true
      try {
        blocklists = await apiGet('/api/fw/blocklists')
      } catch (e) {
        toast('Failed to load blocklists: ' + e.message, 'error')
      } finally {
        loadingBlocklists = false
      }
    }
  }

  async function importBlocklist(source) {
    importingSource = source
    try {
      const body = source === 'custom' ? { url: customURL } : { source }
      const res = await apiPost('/api/fw/blocklists/import', body)
      toast(`Imported ${res.added} IPs from ${res.source} (${res.skipped} skipped)`, 'success')
      if (source === 'custom') customURL = ''
      await reloadSection('blocked')
      await loadStatus()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      importingSource = null
    }
  }

  async function deleteBlockedSource(source) {
    if (!confirm(`Delete all IPs from "${source}"?`)) return
    try {
      const res = await apiDelete(`/api/fw/blocked/source/${source}`)
      toast(`Deleted ${res.deleted} IPs from ${source}`, 'success')
      await reloadSection('blocked')
      await loadStatus()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Helpers
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
    loadSSHPort() // Load SSH port for the SSH change feature
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
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <Tabs {tabs} bind:activeTab urlKey="tab" />

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
              <div class="ml-auto flex items-center gap-3">
                <Button onclick={() => { newSSHPort = sshPort.toString(); showSSHModal = true }} variant="outline" size="sm" icon="key">
                  SSH: {sshPort}
                </Button>
                <span class="text-sm text-slate-500 dark:text-zinc-400">
                  {sortedPorts.length} ports allowed
                </span>
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

              <Button onclick={openImportModal} variant="outline" size="sm" icon="download">
                Import
              </Button>
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
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">IP / Range</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-zinc-500">Source</th>
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
                          <div class="flex items-center gap-2">
                            <code class="text-sm font-mono text-slate-900 dark:text-zinc-100">{blocked.ip}</code>
                            {#if blocked.isRange}
                              <Badge variant="info" size="sm">Range</Badge>
                            {/if}
                          </div>
                          {#if blocked.escalatedFrom}
                            <div class="text-xs text-muted-foreground mt-0.5">
                              Auto-escalated from {blocked.escalatedFrom}
                            </div>
                          {/if}
                        </td>
                        <td class="px-4 py-3 align-top">
                          <button
                            onclick={() => setBlockedJailFilter(blocked.jailName)}
                            class="inline-flex"
                          >
                            <Badge
                              variant={blocked.source === 'manual' ? 'info' : blocked.source?.startsWith('jail:') ? (blocked.jailName === 'sshd' ? 'danger' : 'warning') : 'secondary'}
                              size="sm"
                            >
                              {blocked.source || blocked.jailName || 'manual'}
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
          <!-- Toolbar -->
          <div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 mb-4 dark:border-zinc-800 dark:bg-zinc-900/80">
            <div class="flex flex-wrap items-center gap-3">
              <span class="text-sm text-slate-500 dark:text-zinc-400">
                {jails.length} jail{jails.length !== 1 ? 's' : ''} configured
              </span>
              <div class="ml-auto"></div>
              <Button onclick={openCreateJail} size="sm" icon="plus">
                Add Jail
              </Button>
            </div>
          </div>

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
              <p class="mt-1 text-sm text-slate-500 dark:text-zinc-400">Create a jail to automatically block malicious IPs</p>
              <Button onclick={openCreateJail} size="sm" icon="plus" class="mt-4">
                Create Jail
              </Button>
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
                      {#if jail.escalateEnabled}
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-purple-500/10 text-purple-600 dark:bg-purple-500/20 dark:text-purple-400" title="Auto-escalates to /24 range block when {jail.escalateThreshold}+ IPs blocked">
                          <Icon name="trending-up" size={12} />
                          Auto
                        </span>
                      {/if}
                      <button
                        onclick={() => openEditJail(jail)}
                        class="p-1.5 rounded text-slate-400 hover:text-primary hover:bg-primary/10 transition-colors"
                        title="Edit jail"
                      >
                        <Icon name="edit" size={14} />
                      </button>
                      <button
                        onclick={() => confirmDeleteJail(jail)}
                        class="p-1.5 rounded text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                        title="Delete jail"
                      >
                        <Icon name="trash" size={14} />
                      </button>
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
<Modal bind:open={showBlockModal} title="Block IP or Range" size="sm">
  <div class="space-y-4">
    <Input
      label="IP Address or CIDR Range"
      bind:value={blockForm.ip}
      placeholder="e.g. 192.168.1.100 or 192.168.1.0/24"
      helperText="Use CIDR notation (e.g., /24) to block an entire range"
    />
    <Input
      label="Reason"
      bind:value={blockForm.reason}
      placeholder="Manual block (optional)"
    />
    <div>
      <label class="kt-label">Duration</label>
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

  {#snippet footer()}
    <Button onclick={() => showBlockModal = false} variant="secondary">Cancel</Button>
    <Button onclick={blockIP} variant="destructive" icon="ban">Block</Button>
  {/snippet}
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
  {/if}

  {#snippet footer()}
    <Button onclick={() => { showUnblockModal = false; unblockingIP = null }} variant="secondary">Cancel</Button>
    <Button onclick={unblockIP} icon="lock-open">Unblock</Button>
  {/snippet}
</Modal>

<!-- Change SSH Port Modal -->
<Modal bind:open={showSSHModal} title="Change SSH Port" size="sm">
  <div class="space-y-4">
    <div class="kt-alert kt-alert-warning">
      <Icon name="alert-triangle" size={18} />
      <div>
        <strong>This will change your SSH port.</strong>
        Ensure you can access the server on the new port before closing your session.
      </div>
    </div>

    <div class="flex gap-3">
      <div class="flex-1">
        <label class="kt-label">Current Port</label>
        <div class="kt-input font-mono bg-muted">{sshPort}</div>
      </div>
      <div class="flex-1">
        <Input
          label="New Port"
          type="number"
          bind:value={newSSHPort}
          class="font-mono"
          placeholder="2222"
          min="1"
          max="65535"
        />
      </div>
    </div>

    <p class="text-xs text-muted-foreground">
      Common ports: 2222, 2022, 22022
    </p>
  </div>

  {#snippet footer()}
    <Button onclick={() => showSSHModal = false} variant="secondary" disabled={changingSSH}>
      Cancel
    </Button>
    <Button onclick={changeSSHPort} icon="key" disabled={changingSSH || !newSSHPort || parseInt(newSSHPort) === sshPort}>
      {changingSSH ? 'Changing...' : 'Change Port'}
    </Button>
  {/snippet}
</Modal>

<!-- Create/Edit Jail Modal -->
<Modal bind:open={showJailModal} title={jailForm.id ? 'Edit Jail' : 'Create Jail'} size="md">
  <div class="space-y-4">
    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Name"
        bind:value={jailForm.name}
        placeholder="e.g. sshd, portscan"
        disabled={!!jailForm.id}
      />
      <div>
        <label class="kt-label">Status</label>
        <select bind:value={jailForm.enabled} class="kt-input w-full">
          <option value={true}>Enabled</option>
          <option value={false}>Disabled</option>
        </select>
      </div>
    </div>

    <Input
      label="Log File"
      bind:value={jailForm.logFile}
      placeholder="/var/log/auth.log"
    />

    <Input
      label="Filter Regex"
      bind:value={jailForm.filterRegex}
      placeholder="e.g. Failed password.*from (\d+\.\d+\.\d+\.\d+)"
      class="font-mono"
      helperText="Must contain at least one capture group for the IP address"
    />

    <div class="grid grid-cols-3 gap-4">
      <Input
        label="Max Retry"
        type="number"
        bind:value={jailForm.maxRetry}
        min="1"
        max="100"
      />
      <div>
        <label class="kt-label">Find Time</label>
        <select bind:value={jailForm.findTime} class="kt-input w-full">
          <option value={300}>5 minutes</option>
          <option value={600}>10 minutes</option>
          <option value={1800}>30 minutes</option>
          <option value={3600}>1 hour</option>
          <option value={7200}>2 hours</option>
          <option value={86400}>24 hours</option>
        </select>
      </div>
      <div>
        <label class="kt-label">Ban Time</label>
        <select bind:value={jailForm.banTime} class="kt-input w-full">
          <option value={3600}>1 hour</option>
          <option value={86400}>1 day</option>
          <option value={604800}>7 days</option>
          <option value={2592000}>30 days</option>
          <option value={31536000}>1 year</option>
          <option value={-1}>Permanent</option>
        </select>
      </div>
    </div>

    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Port"
        bind:value={jailForm.port}
        placeholder="all or specific port"
      />
      <div>
        <label class="kt-label">Action</label>
        <select bind:value={jailForm.action} class="kt-input w-full">
          <option value="drop">Drop</option>
          <option value="reject">Reject</option>
        </select>
      </div>
    </div>

    <!-- Auto-Escalation Settings -->
    <div class="border-t border-slate-200 dark:border-zinc-700 pt-4 mt-4">
      <div class="flex items-center justify-between mb-3">
        <div>
          <label class="kt-label mb-0">Auto-Escalation</label>
          <p class="text-xs text-muted-foreground">Automatically block entire /24 range when threshold IPs are blocked</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={jailForm.escalateEnabled} class="sr-only peer">
          <div class="w-9 h-5 bg-slate-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-zinc-600 peer-checked:bg-primary"></div>
        </label>
      </div>

      {#if jailForm.escalateEnabled}
        <div class="grid grid-cols-2 gap-4 p-3 bg-slate-50 dark:bg-zinc-800/50 rounded-lg">
          <Input
            label="IP Threshold"
            type="number"
            bind:value={jailForm.escalateThreshold}
            min="2"
            max="20"
            helperText="Block /24 when this many IPs blocked"
          />
          <div>
            <label class="kt-label">Time Window</label>
            <select bind:value={jailForm.escalateWindow} class="kt-input w-full">
              <option value={1800}>30 minutes</option>
              <option value={3600}>1 hour</option>
              <option value={7200}>2 hours</option>
              <option value={14400}>4 hours</option>
              <option value={86400}>24 hours</option>
            </select>
          </div>
        </div>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={() => showJailModal = false} variant="secondary" disabled={savingJail}>
      Cancel
    </Button>
    <Button onclick={saveJail} icon={jailForm.id ? 'check' : 'plus'} disabled={savingJail}>
      {savingJail ? 'Saving...' : (jailForm.id ? 'Save Changes' : 'Create Jail')}
    </Button>
  {/snippet}
</Modal>

<!-- Delete Jail Confirmation Modal -->
<Modal bind:open={showDeleteJailModal} title="Delete Jail" size="sm">
  {#if deletingJail}
    <div class="text-center">
      <div class="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center mx-auto mb-4">
        <Icon name="trash" size={24} class="text-destructive" />
      </div>
      <p class="text-foreground mb-2">
        Delete jail <strong>{deletingJail.name}</strong>?
      </p>
      <p class="text-sm text-muted-foreground">
        This will stop the jail monitor and remove all associated blocked IPs.
      </p>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => { showDeleteJailModal = false; deletingJail = null }} variant="secondary">
      Cancel
    </Button>
    <Button onclick={deleteJail} variant="destructive" icon="trash">
      Delete Jail
    </Button>
  {/snippet}
</Modal>

<!-- Blocklist Import Modal -->
<Modal bind:open={showImportModal} title="Import Blocklist" size="md">
  <div class="space-y-5">
    {#if loadingBlocklists}
      <div class="flex flex-col items-center justify-center py-8">
        <div class="w-6 h-6 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
        <p class="mt-2 text-sm text-muted-foreground">Loading sources...</p>
      </div>
    {:else}
      <!-- Internet Scanners -->
      <div>
        <h4 class="text-sm font-medium text-foreground mb-2">Internet Scanners</h4>
        <p class="text-xs text-muted-foreground mb-3">Block known scanning services like Censys, Shodan</p>
        <div class="flex flex-wrap gap-2">
          {#each blocklists.filter(b => b.id === 'censys' || b.id === 'shodan') as source}
            <Button
              onclick={() => importBlocklist(source.id)}
              variant="outline"
              size="sm"
              disabled={importingSource === source.id}
            >
              {#if importingSource === source.id}
                <div class="w-3 h-3 border-2 border-muted border-t-primary rounded-full animate-spin mr-1"></div>
              {/if}
              {source.name}
              <span class="text-xs text-muted-foreground ml-1">(~{source.count})</span>
            </Button>
          {/each}
        </div>
      </div>

      <!-- Threat Intelligence -->
      <div>
        <h4 class="text-sm font-medium text-foreground mb-2">Threat Intelligence</h4>
        <p class="text-xs text-muted-foreground mb-3">IP addresses flagged as malicious by multiple sources</p>
        <div class="flex flex-wrap gap-2">
          {#each blocklists.filter(b => b.id.startsWith('ipsum') || b.id.startsWith('firehol')) as source}
            <Button
              onclick={() => importBlocklist(source.id)}
              variant="outline"
              size="sm"
              disabled={importingSource === source.id}
            >
              {#if importingSource === source.id}
                <div class="w-3 h-3 border-2 border-muted border-t-primary rounded-full animate-spin mr-1"></div>
              {/if}
              {source.name}
              <span class="text-xs text-muted-foreground ml-1">(~{source.count?.toLocaleString()})</span>
            </Button>
          {/each}
        </div>
      </div>

      <!-- Custom URL -->
      <div>
        <h4 class="text-sm font-medium text-foreground mb-2">Custom URL</h4>
        <p class="text-xs text-muted-foreground mb-3">Import from any IP/CIDR list URL</p>
        <div class="flex gap-2">
          <Input
            bind:value={customURL}
            placeholder="https://example.com/blocklist.txt"
            class="flex-1"
          />
          <Button
            onclick={() => importBlocklist('custom')}
            variant="outline"
            size="sm"
            disabled={!customURL || importingSource === 'custom'}
          >
            {#if importingSource === 'custom'}
              <div class="w-3 h-3 border-2 border-muted border-t-primary rounded-full animate-spin mr-1"></div>
            {/if}
            Import
          </Button>
        </div>
        <p class="text-xs text-muted-foreground mt-2">Supports: plain IP lists, CIDR notation, ipsum format, FireHOL netset</p>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <Button onclick={() => showImportModal = false} variant="secondary">Close</Button>
  {/snippet}
</Modal>
