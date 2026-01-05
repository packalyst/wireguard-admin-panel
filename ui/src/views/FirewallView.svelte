<script>
  import { onMount, onDestroy, untrack } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, getInitialTab, confirm, setConfirmLoading } from '../stores/app.js'
  import { loadState, saveState, createDebouncedSearch, getDefaultPerPage, lazyLoad } from '../stores/helpers.js'
  import { generalInfoStore } from '../stores/websocket.js'
  import { timeAgo, formatRelativeDate, formatTime } from '$lib/utils/format.js'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import Pagination from '../components/Pagination.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import Button from '../components/Button.svelte'
  import Tabs from '../components/Tabs.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import DropdownButton from '../components/DropdownButton.svelte'
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

  // Blocked entries state (server-side pagination)
  let blockedEntries = $state([])
  let blockedTotal = $state(0)
  let blockedTypes = $state([])
  let blockedSources = $state([])
  let loadingBlocked = $state(false)
  let removingEntryId = $state(null)
  let selectedBlockedEntries = $state([])
  let deletingSelectedEntries = $state(false)

  // Attempts state (server-side pagination)
  let attempts = $state([])
  let attemptsTotal = $state(0)
  let attemptsJails = $state([])
  let loadingAttempts = $state(false)

  // Load saved state from localStorage
  const savedBlockedState = loadState('firewall_blocked')
  const savedAttemptsState = loadState('firewall_attempts')

  // UI state - read initial tab from URL hash
  let activeTab = $state(getInitialTab('ports', ['ports', 'blocked', 'attempts', 'jails']))

  // Blocked tab state
  let blockedPage = $state(savedBlockedState.page || 1)
  let blockedPerPage = $state(savedBlockedState.perPage || getDefaultPerPage())
  let blockedSearch = $state(savedBlockedState.search || '')
  let blockedTypeFilter = $state(savedBlockedState.type || '')
  let blockedSourceFilter = $state(savedBlockedState.source || '')
  let blockedSearchQuery = $state(savedBlockedState.search || '')

  // Attempts tab state
  let attemptsPage = $state(savedAttemptsState.page || 1)
  let attemptsPerPage = $state(savedAttemptsState.perPage || getDefaultPerPage())
  let attemptsSearch = $state(savedAttemptsState.search || '')
  let attemptsJailFilter = $state(savedAttemptsState.jail || '')
  let attemptsSearchQuery = $state(savedAttemptsState.search || '')

  // Derived - offsets for API calls
  const blockedOffset = $derived((blockedPage - 1) * blockedPerPage)
  const attemptsOffset = $derived((attemptsPage - 1) * attemptsPerPage)

  // Save state to localStorage
  $effect(() => {
    saveState('firewall_blocked', {
      page: blockedPage,
      perPage: blockedPerPage,
      search: blockedSearch,
      type: blockedTypeFilter,
      source: blockedSourceFilter
    })
  })

  $effect(() => {
    saveState('firewall_attempts', {
      page: attemptsPage,
      perPage: attemptsPerPage,
      search: attemptsSearch,
      jail: attemptsJailFilter
    })
  })

  // Listen for WebSocket zone progress updates via custom event
  // (store-based approach misses rapid messages)
  function handleZoneUpdate(e) {
    const info = e.detail
    if (!info?.event) return

    if (info.event === 'firewall:zones:progress' && info.country && info.rangeCount !== undefined) {
      // Update the hitCount for this country in blockedEntries
      blockedEntries = blockedEntries.map(entry => {
        if (entry.entryType === 'country' && entry.value === info.country) {
          return { ...entry, hitCount: info.rangeCount }
        }
        return entry
      })
    } else if (info.event === 'firewall:zones:complete') {
      // Reload blocked entries to get final state
      loadBlocked()
    }
  }

  onMount(() => {
    window.addEventListener('firewall-zone-update', handleZoneUpdate)
  })

  onDestroy(() => {
    window.removeEventListener('firewall-zone-update', handleZoneUpdate)
  })

  // Modals
  let showBlockModal = $state(false)
  let showSSHModal = $state(false)
  let showJailModal = $state(false)

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

  // Sync status state
  let syncStatus = $state(null)
  let checkingSyncStatus = $state(false)
  let refreshingZones = $state(false)

  // Country blocking state
  let availableCountries = $state([])
  let showBlockCountriesModal = $state(false)
  let countrySearch = $state('')
  let selectedCountries = $state([])
  let blockingCountries = $state(false)

  // Load status on mount
  async function loadStatus() {
    try {
      status = await apiGet('/api/fw/status')
      // Extract sshPort from status (no longer separate API call)
      if (status?.sshPort) {
        sshPort = status.sshPort
      }
    } catch {
      // Ignore errors
    } finally {
      loading = false
    }
  }

  // Check sync status between DB and nftables
  async function checkSyncStatus() {
    checkingSyncStatus = true
    try {
      syncStatus = await apiGet('/api/fw/sync-status')
      if (!syncStatus.inSync) {
        if (syncStatus.lastApplyError) {
          toast('Firewall sync error: ' + syncStatus.lastApplyError, 'error')
        } else if (!syncStatus.nftTableExists) {
          toast('Firewall table not found in nftables', 'warning')
        } else {
          // Show detailed mismatch info
          const mismatches = []
          if (syncStatus.dbBlockedIPs !== syncStatus.nftBlockedIPs) {
            mismatches.push(`IPs: DB=${syncStatus.dbBlockedIPs} vs NFT=${syncStatus.nftBlockedIPs}`)
          }
          if (syncStatus.dbBlockedRanges !== syncStatus.nftBlockedRanges) {
            mismatches.push(`Ranges: DB=${syncStatus.dbBlockedRanges} vs NFT=${syncStatus.nftBlockedRanges}`)
          }
          if (syncStatus.dbAllowedPorts !== syncStatus.nftAllowedPorts) {
            mismatches.push(`Ports: DB=${syncStatus.dbAllowedPorts} vs NFT=${syncStatus.nftAllowedPorts}`)
          }
          if (syncStatus.dbCountryRanges !== syncStatus.nftCountryRanges) {
            mismatches.push(`Countries: DB=${syncStatus.dbCountryRanges} vs NFT=${syncStatus.nftCountryRanges}`)
          }
          if (syncStatus.applyPending) {
            mismatches.push('Apply pending')
          }
          toast('Out of sync: ' + mismatches.join(', '), 'warning')
        }
      } else {
        const parts = [`${syncStatus.dbBlockedIPs} IPs`, `${syncStatus.dbAllowedPorts} ports`]
        if (syncStatus.dbBlockedRanges > 0) parts.push(`${syncStatus.dbBlockedRanges} ranges`)
        if (syncStatus.dbCountryRanges > 0) parts.push(`${syncStatus.dbCountryRanges} country ranges`)
        toast(`In sync: ${parts.join(', ')}`, 'success')
      }
    } catch (e) {
      toast('Failed to check sync status: ' + e.message, 'error')
    } finally {
      checkingSyncStatus = false
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
        offset: blockedOffset.toString(),
        action: 'block' // Only show blocked entries (not allowed ports)
      })
      if (blockedSearch) params.set('search', blockedSearch)
      if (blockedTypeFilter) params.set('type', blockedTypeFilter)
      if (blockedSourceFilter) params.set('source', blockedSourceFilter)

      const res = await apiGet(`/api/fw/entries?${params}`)
      blockedEntries = res.entries || []
      blockedTotal = res.total || 0
      blockedTypes = res.types || []
      blockedSources = res.sources || []
    } catch (e) {
      toast('Failed to load blocked entries: ' + e.message, 'error')
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
  const debouncedBlockedSearch = createDebouncedSearch((value) => {
    blockedSearch = value
    blockedPage = 1
    loadBlocked()
  })

  const debouncedAttemptsSearch = createDebouncedSearch((value) => {
    attemptsSearch = value
    attemptsPage = 1
    loadAttempts()
  })

  function handleBlockedSearchInput(e) {
    blockedSearchQuery = e.target.value
    debouncedBlockedSearch(blockedSearchQuery)
  }

  function handleAttemptsSearchInput(e) {
    attemptsSearchQuery = e.target.value
    debouncedAttemptsSearch(attemptsSearchQuery)
  }

  function setBlockedTypeFilter(type) {
    blockedTypeFilter = type
    blockedPage = 1
    loadBlocked()
  }

  function setBlockedSourceFilter(source) {
    blockedSourceFilter = source
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
    blockedTypeFilter = ''
    blockedSourceFilter = ''
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

  // Tab change handler - called when user clicks a tab
  function handleTabChange(tabId) {
    if (tabId === 'ports') loadPorts()
    else if (tabId === 'blocked') loadBlocked()
    else if (tabId === 'attempts') loadAttempts()
    else if (tabId === 'jails') loadJails()
  }

  // Load initial tab data based on URL or default
  function loadInitialTab() {
    handleTabChange(activeTab)
  }

  // Sorted ports (avoid mutation in template)
  const sortedPorts = $derived.by(() => {
    const arr = ports || []
    if (!arr.slice) return []
    return [...arr].sort((a, b) => a.port - b.port)
  })

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
      const isRange = cidrRegex.test(blockForm.ip)
      const res = await apiPost('/api/fw/entries', {
        type: isRange ? 'range' : 'ip',
        value: blockForm.ip,
        action: 'block',
        direction: 'inbound',
        reason: blockForm.reason || 'Manual block',
        banTime
      })
      const msg = isRange ? `Range ${blockForm.ip} blocked` : `IP ${blockForm.ip} blocked`
      toast(msg, 'success')
      showBlockModal = false
      blockForm = { ip: '', reason: '', duration: '30d' }
      await reloadSection('blocked')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function confirmUnblock(entry) {
    const label = entry.entryType === 'country' ? (entry.name || entry.value) : entry.value
    const description = entry.entryType === 'country'
      ? 'Traffic from this country will be allowed again.'
      : entry.entryType === 'range'
        ? 'This IP range will be able to connect again.'
        : 'This IP will be able to connect again.'

    const confirmed = await confirm({
      title: 'Unblock Entry',
      message: `Unblock ${label}?`,
      description,
      confirmText: 'Unblock',
      variant: 'success'
    })
    if (!confirmed) return

    removingEntryId = entry.id
    setConfirmLoading(true)
    try {
      await apiDelete(`/api/fw/entries/${entry.id}`)
      toast(`${label} unblocked`, 'success')
      await reloadSection('blocked')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      removingEntryId = null
      setConfirmLoading(false)
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

  async function confirmDeleteJail(jail) {
    const confirmed = await confirm({
      title: 'Delete Jail',
      message: `Delete jail "${jail.name}"?`,
      description: 'This will stop the jail monitor and remove all associated blocked IPs.',
      confirmText: 'Delete Jail'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiDelete(`/api/fw/jails/${jail.name}`)
      toast(`Jail "${jail.name}" deleted`, 'success')
      await reloadSection('jails')
      await loadStatus()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
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
      const res = await apiPost('/api/fw/entries/import', body)
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

  async function toggleEntryDirection(entry) {
    const newDirection = entry.direction === 'inbound' ? 'both' : 'inbound'
    try {
      await apiPost(`/api/fw/entries/${entry.id}/toggle`, { direction: newDirection })
      const label = entry.entryType === 'country' ? entry.name || entry.value : entry.value
      toast(`${label} direction changed to ${newDirection}`, 'success')
      await loadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Toggle blocked entry selection
  function toggleBlockedEntrySelection(id) {
    if (selectedBlockedEntries.includes(id)) {
      selectedBlockedEntries = selectedBlockedEntries.filter(e => e !== id)
    } else {
      selectedBlockedEntries = [...selectedBlockedEntries, id]
    }
  }

  // Select/deselect all blocked entries
  function toggleAllBlockedEntries() {
    if (selectedBlockedEntries.length === blockedEntries.length) {
      selectedBlockedEntries = []
    } else {
      selectedBlockedEntries = blockedEntries.map(e => e.id)
    }
  }

  // Delete selected blocked entries
  async function deleteSelectedBlockedEntries() {
    if (selectedBlockedEntries.length === 0) return
    deletingSelectedEntries = true
    const toDelete = [...selectedBlockedEntries]

    try {
      const result = await apiPost('/api/fw/entries/bulk', {
        action: 'delete',
        ids: toDelete
      })
      selectedBlockedEntries = []
      await loadBlocked()
      await loadStatus()
      toast(`Deleted ${result.affected} entries`, 'success')
    } catch (e) {
      toast(`Failed to delete entries: ${e.message}`, 'error')
    } finally {
      deletingSelectedEntries = false
    }
  }

  // Set direction for selected entries
  async function setSelectedDirection(direction) {
    if (selectedBlockedEntries.length === 0) return
    try {
      const result = await apiPost('/api/fw/entries/bulk', {
        action: `set_${direction}`,
        ids: [...selectedBlockedEntries]
      })
      selectedBlockedEntries = []
      await loadBlocked()
      toast(`Updated ${result.affected} entries to ${direction}`, 'success')
    } catch (e) {
      toast(`Failed to update entries: ${e.message}`, 'error')
    }
  }

  // Delete all entries
  async function confirmDeleteAll() {
    const confirmed = await confirm({
      title: 'Delete All Entries',
      message: `This will permanently delete ${blockedTotal} blocked entries.`,
      description: 'All IPs, ranges, and countries will be removed. Essential entries (system ports) will not be deleted.',
      warning: 'This action cannot be undone!',
      confirmText: 'Delete All'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      const result = await apiDelete('/api/fw/entries/all')
      await loadBlocked()
      await loadStatus()
      toast(`Deleted ${result.deleted} entries`, 'success')
    } catch (e) {
      toast(`Failed to delete entries: ${e.message}`, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  async function refreshZones() {
    refreshingZones = true
    try {
      const res = await apiPost('/api/geo/zones/refresh')
      toast(`Refreshed ${res.updated} countries${res.errors > 0 ? ` (${res.errors} errors)` : ''}`, res.errors > 0 ? 'warning' : 'success')
      await loadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      refreshingZones = false
    }
  }

  // Country blocking functions
  async function loadCountries() {
    try {
      const res = await apiGet('/api/geo/countries')
      availableCountries = res.countries || res || []
    } catch (e) {
      toast('Failed to load countries: ' + e.message, 'error')
    }
  }

  function openBlockCountriesModal() {
    loadCountries()
    showBlockCountriesModal = true
  }

  // Get list of blocked country codes from blocked entries
  const blockedCountryCodes = $derived(
    blockedEntries
      .filter(e => e.entryType === 'country')
      .map(e => e.value)
  )

  // Filter out already blocked countries
  const unblockedCountries = $derived(
    availableCountries.filter(c => !blockedCountryCodes.includes(c.code))
  )

  // Filtered by search
  const filteredUnblockedCountries = $derived(
    countrySearch
      ? unblockedCountries.filter(c =>
          c.name.toLowerCase().includes(countrySearch.toLowerCase()) ||
          c.code.toLowerCase().includes(countrySearch.toLowerCase())
        )
      : unblockedCountries
  )

  // Group by continent
  const countriesByContinent = $derived.by(() => {
    const groups = {}
    for (const country of filteredUnblockedCountries) {
      const continent = country.continent || 'Other'
      if (!groups[continent]) groups[continent] = []
      groups[continent].push(country)
    }
    return groups
  })

  const sortedContinents = $derived(
    Object.keys(countriesByContinent).sort()
  )

  function toggleCountrySelection(code) {
    if (selectedCountries.includes(code)) {
      selectedCountries = selectedCountries.filter(c => c !== code)
    } else {
      selectedCountries = [...selectedCountries, code]
    }
  }

  function selectAllFilteredCountries() {
    selectedCountries = filteredUnblockedCountries.map(c => c.code)
  }

  function clearCountrySelection() {
    selectedCountries = []
  }

  function toggleContinentSelection(continent) {
    const continentCountries = countriesByContinent[continent] || []
    const continentCodes = continentCountries.map(c => c.code)
    const allSelected = continentCodes.every(c => selectedCountries.includes(c))

    if (allSelected) {
      selectedCountries = selectedCountries.filter(c => !continentCodes.includes(c))
    } else {
      const newSelection = new Set([...selectedCountries, ...continentCodes])
      selectedCountries = [...newSelection]
    }
  }

  function isContinentFullySelected(continent) {
    const continentCountries = countriesByContinent[continent] || []
    return continentCountries.length > 0 && continentCountries.every(c => selectedCountries.includes(c.code))
  }

  function isContinentPartiallySelected(continent) {
    const continentCountries = countriesByContinent[continent] || []
    const selectedCount = continentCountries.filter(c => selectedCountries.includes(c.code)).length
    return selectedCount > 0 && selectedCount < continentCountries.length
  }

  async function blockSelectedCountries() {
    if (selectedCountries.length === 0) return
    blockingCountries = true
    try {
      // Create country entries via the entries API
      for (const code of selectedCountries) {
        const country = availableCountries.find(c => c.code === code)
        await apiPost('/api/fw/entries', {
          type: 'country',
          value: code,
          name: country?.name || code,
          action: 'block',
          direction: 'inbound',
          reason: 'Country block'
        })
      }
      toast(`Blocking ${selectedCountries.length} countries...`, 'info')
      showBlockCountriesModal = false
      selectedCountries = []
      countrySearch = ''
      // Reload blocked entries to show new countries
      await loadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      blockingCountries = false
    }
  }

  // Helpers
  function formatTimeRemaining(expiresAt) {
    if (!expiresAt) return 'Permanent'
    const expStr = typeof expiresAt === 'string' ? expiresAt : expiresAt.toISOString?.() || String(expiresAt)
    if (expStr.startsWith('0001-')) return 'Permanent'
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
    loadInitialTab() // Load data for the active tab (from URL or default)
  })

  onDestroy(() => {
    // Cleanup handled by createDebouncedSearch helper
  })
</script>

{#if loading}
  <div class="flex flex-col items-center justify-center py-12">
    <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    <p class="mt-3 text-sm text-muted-foreground">Loading firewall...</p>
  </div>
{:else}
  <div class="space-y-4">
    <!-- Info Card -->
    <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
      <div class="flex items-start gap-3">
        <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
          <Icon name="shield" size={18} class="text-primary" />
        </div>
        <div class="flex-1 min-w-0">
          <h3 class="text-sm font-medium text-foreground mb-1">
            Firewall Active
          </h3>
          <p class="text-xs text-muted-foreground leading-relaxed">
            Default policy: <strong>{status?.defaultPolicy || 'drop'}</strong>. Managing ports, blocked IPs, country blocking, and intrusion detection jails.
          </p>
        </div>
        <div class="hidden sm:flex items-center gap-6 text-center">
          <div>
            <div class="text-lg font-bold text-foreground">{status?.blockedIPCount || 0}</div>
            <div class="text-[10px] text-muted-foreground">Blocked</div>
          </div>
          <div>
            <div class="text-lg font-bold text-foreground">{status?.activeJails || 0}</div>
            <div class="text-[10px] text-muted-foreground">Jails</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Tabs Card -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <Tabs {tabs} bind:activeTab urlKey="tab" onchange={handleTabChange} />

      <!-- Tab Content -->
      <div class="p-5">
        <!-- Ports Tab -->
        {#if activeTab === 'ports'}
          <!-- Add Port Toolbar -->
          <div class="rounded-xl border border-border bg-muted/80 px-4 py-3 mb-4">
            <div class="flex flex-wrap items-center gap-3">
              <Input
                type="number"
                bind:value={newPort}
                placeholder="Port number"
                prefixIcon="plug"
                suffixAddonBtn={{ icon: "plus", onclick: addPort }}
                class="w-40"
                min="1"
                max="65535"
                onkeydown={(e) => e.key === 'Enter' && addPort()}
              />
              <div class="ml-auto">
                <Button onclick={() => { newSSHPort = sshPort.toString(); showSSHModal = true }} variant="outline" size="sm" icon="key">
                  SSH: {sshPort}
                </Button>
              </div>
            </div>
          </div>

          {#if loadingPorts}
            <div class="flex flex-col items-center justify-center py-8">
              <div class="w-6 h-6 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              <p class="mt-2 text-sm text-muted-foreground">Loading ports...</p>
            </div>
          {:else if sortedPorts.length > 0}
            <div class="rounded-xl border border-border bg-card overflow-hidden">
              <div class="overflow-x-auto">
                <table class="w-full">
                  <thead>
                    <tr class="border-b border-border">
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Port</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Protocol</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Type</th>
                      <th class="px-4 py-3 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Service</th>
                      <th class="px-4 py-3 w-10"></th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-border/50">
                    {#each sortedPorts as p}
                      <tr class="group hover:bg-muted/50 transition-colors">
                        <td class="px-4 py-3 align-middle">
                          <code class="text-sm font-mono font-semibold text-foreground">{p.port}</code>
                        </td>
                        <td class="px-4 py-3 align-middle">
                          <span class="inline-flex items-center justify-center min-w-[42px] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide rounded-md bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400">
                            {p.protocol || 'tcp'}
                          </span>
                        </td>
                        <td class="px-4 py-3 align-middle">
                          {#if p.essential}
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-md bg-warning/10 text-warning">
                              <Icon name="shield-check" size={12} />
                              Essential
                            </span>
                          {:else}
                            <span class="text-xs text-muted-foreground">Custom</span>
                          {/if}
                        </td>
                        <td class="px-4 py-3 align-middle text-sm text-muted-foreground">
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
                              class="icon-btn-destructive"
                              title="Remove port"
                            >
                              <Icon name="trash" size={14} />
                            </button>
                          {:else}
                            <span class="p-1.5 text-dim">
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
            <EmptyState
              icon="shield"
              title="No ports configured"
              description="Add ports to allow traffic through the firewall"
              large
            />
          {/if}

        <!-- Blocked Tab -->
        {:else if activeTab === 'blocked'}
          <div class="data-table">
            <!-- Header -->
            <div class="data-table-header">
              <div class="data-table-header-start">
                <Input
                  type="search"
                  value={blockedSearchQuery}
                  oninput={handleBlockedSearchInput}
                  placeholder="Search IP, country, reason..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
                {#if blockedTypes.length > 1}
                  <Select
                    value={blockedTypeFilter}
                    onchange={(e) => setBlockedTypeFilter(e.target.value)}
                    class="sm:w-32"
                  >
                    <option value="">All types</option>
                    {#each blockedTypes as type}
                      <option value={type}>{type}</option>
                    {/each}
                  </Select>
                {/if}
                {#if blockedSources.length > 1}
                  <Select
                    value={blockedSourceFilter}
                    onchange={(e) => setBlockedSourceFilter(e.target.value)}
                    class="sm:w-36"
                  >
                    <option value="">All sources</option>
                    {#each blockedSources as source}
                      <option value={source}>{source}</option>
                    {/each}
                  </Select>
                {/if}
              </div>
              <div class="data-table-header-end">
                <div class="kt-btn-group">
                  <!-- Block dropdown -->
                  <DropdownButton
                    label="Block"
                    icon="plus"
                    items={[
                      { label: 'IP / Range', icon: 'ban', onclick: () => showBlockModal = true },
                      { label: 'Import Blocklist', icon: 'download', onclick: openImportModal },
                      ...(status?.countryBlockingEnabled ? [
                        { divider: true },
                        { label: 'Countries', icon: 'world', onclick: openBlockCountriesModal }
                      ] : [])
                    ]}
                  />

                  <!-- Actions dropdown -->
                  <DropdownButton
                    label="Actions"
                    icon="settings"
                    variant="outline"
                    items={[
                      { label: refreshingZones ? 'Refreshing...' : 'Refresh Zones', icon: 'refresh', iconClass: refreshingZones ? 'animate-spin' : '', onclick: refreshZones, disabled: refreshingZones || !status?.countryBlockingEnabled },
                      { label: checkingSyncStatus ? 'Checking...' : 'Check Sync', icon: 'circle-check', onclick: checkSyncStatus, disabled: checkingSyncStatus },
                      { divider: true },
                      { label: 'Delete All...', icon: 'trash', variant: 'destructive', onclick: confirmDeleteAll, disabled: blockedTotal === 0 }
                    ]}
                  />

                  <!-- Bulk dropdown (when items selected) -->
                  {#if selectedBlockedEntries.length > 0}
                    <DropdownButton
                      label="Bulk ({selectedBlockedEntries.length})"
                      icon="layers-subtract"
                      variant="destructive"
                      items={[
                        { label: 'Delete', icon: 'trash', variant: 'destructive', onclick: deleteSelectedBlockedEntries },
                        { divider: true },
                        { label: 'Set Inbound', icon: 'arrow-down', onclick: () => setSelectedDirection('inbound') },
                        { label: 'Set Both', icon: 'arrows-vertical', onclick: () => setSelectedDirection('both') }
                      ]}
                    />
                  {/if}
                </div>
              </div>
            </div>

            <!-- Content -->
            {#if loadingBlocked && blockedEntries.length === 0}
              <div class="data-table-loading">
                <LoadingSpinner size="lg" />
              </div>
            {:else if blockedEntries.length === 0}
              <div class="data-table-empty">
                <EmptyState
                  icon="shield-check"
                  title="No blocked entries"
                  description={blockedSearch || blockedTypeFilter || blockedSourceFilter ? 'No results match your filters' : 'IPs, ranges, and countries will appear here when blocked'}
                />
              </div>
            {:else}
              <div class="data-table-content">
                <table>
                  <thead>
                    <tr>
                      <th class="w-8">
                        <Checkbox
                          checked={blockedEntries.length > 0 && selectedBlockedEntries.length === blockedEntries.length}
                          indeterminate={selectedBlockedEntries.length > 0 && selectedBlockedEntries.length < blockedEntries.length}
                          onchange={() => toggleAllBlockedEntries()}
                        />
                      </th>
                      <th>Added / Source</th>
                      <th>Value</th>
                      <th>Direction</th>
                      <th>Expires</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each blockedEntries as entry}
                      <tr class="{removingEntryId === entry.id ? 'opacity-50' : ''} {selectedBlockedEntries.includes(entry.id) ? 'bg-primary/5' : ''}">
                        <td>
                          <Checkbox
                            checked={selectedBlockedEntries.includes(entry.id)}
                            onchange={() => toggleBlockedEntrySelection(entry.id)}
                            disabled={removingEntryId === entry.id}
                          />
                        </td>
                        <td class="data-table-cell-nowrap">
                          <div class="flex items-center gap-1.5">
                            <Icon name="clock" size={14} class="text-muted-foreground" />
                            <div>
                              <div class="text-xs font-medium">{formatRelativeDate(entry.createdAt)}, {formatTime(entry.createdAt)}</div>
                              <button onclick={() => setBlockedSourceFilter(entry.source)} class="text-[10px] text-muted-foreground hover:text-foreground">
                                {entry.source || 'manual'}
                              </button>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div class="flex items-center gap-2">
                            {#if entry.entryType === 'country'}
                              <img
                                src="https://flagcdn.com/{entry.value.toLowerCase()}.svg"
                                width="18"
                                alt={entry.value}
                                class="rounded-sm shadow-sm"
                                loading="lazy"
                              />
                              <span class="text-sm font-medium">{entry.name || entry.value}</span>
                              <Badge variant="secondary" size="sm" title="{entry.hitCount || 0} IP ranges">
                                <Icon name="network" size={10} class="mr-0.5" />
                                {(entry.hitCount || 0).toLocaleString()}
                              </Badge>
                            {:else}
                              <Icon name={entry.entryType === 'range' ? 'network' : 'globe'} size={14} class="text-muted-foreground" />
                              <code class="text-xs font-mono">{entry.value}</code>
                              {#if entry.entryType === 'range'}
                                <Badge variant="info" size="sm">Range</Badge>
                              {/if}
                            {/if}
                          </div>
                          {#if entry.reason && entry.entryType !== 'country'}
                            <div class="text-[10px] text-muted-foreground mt-0.5 ml-5 truncate max-w-48" title={entry.reason}>
                              {entry.reason}
                            </div>
                          {/if}
                        </td>
                        <td class="data-table-cell-nowrap">
                          <button
                            onclick={() => toggleEntryDirection(entry)}
                            class="cursor-pointer hover:opacity-80 transition-opacity"
                            disabled={removingEntryId === entry.id}
                          >
                            <Badge variant={entry.direction === 'both' ? 'warning' : 'secondary'} size="sm">
                              {#if entry.direction === 'both'}
                                <Icon name="arrow-left" size={10} class="mr-0.5" />
                                <Icon name="arrow-right" size={10} class="mr-1" />
                                Both
                              {:else if entry.direction === 'outbound'}
                                <Icon name="arrow-right" size={10} class="mr-1" />
                                Out
                              {:else}
                                <Icon name="arrow-left" size={10} class="mr-1" />
                                In
                              {/if}
                            </Badge>
                          </button>
                        </td>
                        <td class="data-table-cell-nowrap">
                          {#if entry.expiresAt}
                            <Badge variant="warning" size="sm">
                              {formatTimeRemaining(entry.expiresAt)}
                            </Badge>
                          {:else}
                            <Badge variant="mono" size="sm">Permanent</Badge>
                          {/if}
                        </td>
                        <td class="data-table-cell-actions">
                          {#if removingEntryId === entry.id}
                            <div class="w-4 h-4 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
                          {:else if entry.essential}
                            <span class="p-1.5 text-dim" title="Essential entry">
                              <Icon name="lock" size={14} />
                            </span>
                          {:else}
                            <button onclick={() => confirmUnblock(entry)} class="icon-btn" title="Unblock">
                              <Icon name="lock-open" size={14} />
                            </button>
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
                  bind:page={blockedPage}
                  bind:perPage={blockedPerPage}
                  total={blockedTotal}
                  onPageChange={loadBlocked}
                />
              </div>
            {/if}
          </div>

        <!-- Activity Tab -->
        {:else if activeTab === 'attempts'}
          <div class="data-table">
            <!-- Header -->
            <div class="data-table-header">
              <div class="data-table-header-start">
                <Input
                  type="search"
                  value={attemptsSearchQuery}
                  oninput={handleAttemptsSearchInput}
                  placeholder="Search IP, port..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
                {#if attemptsJails.length > 0}
                  <Select
                    value={attemptsJailFilter}
                    onchange={(e) => setAttemptsJailFilter(e.target.value)}
                    class="sm:w-40"
                  >
                    <option value="">All jails</option>
                    {#each attemptsJails as jail}
                      <option value={jail}>{jail}</option>
                    {/each}
                  </Select>
                {/if}
              </div>
              <div class="data-table-header-end">
                <div class="kt-btn-group">
                  <Button
                    onclick={clearAttemptsFilters}
                    variant="outline"
                    size="sm"
                    icon="x"
                    disabled={!attemptsSearch && !attemptsJailFilter}
                  >
                    Clear
                  </Button>
                  <Button
                    onclick={() => loadAttempts()}
                    variant="outline"
                    size="sm"
                    icon="refresh"
                  >
                    Refresh
                  </Button>
                </div>
              </div>
            </div>

            <!-- Content -->
            {#if loadingAttempts && attempts.length === 0}
              <div class="data-table-loading">
                <LoadingSpinner size="lg" />
              </div>
            {:else if attempts.length === 0}
              <div class="data-table-empty">
                <EmptyState
                  icon="activity"
                  title="No activity"
                  description={attemptsSearch || attemptsJailFilter ? 'No results match your filters' : 'Connection attempts will appear here when logged'}
                />
              </div>
            {:else}
              <div class="data-table-content">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source IP</th>
                      <th class="text-right">Port</th>
                      <th class="text-center">Jail</th>
                      <th class="text-center">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each attempts as attempt}
                      <tr>
                        <td class="data-table-cell-nowrap">
                          <div class="flex items-center gap-1.5">
                            <Icon name="clock" size={14} class="text-muted-foreground" />
                            <span class="text-xs font-medium">{formatRelativeDate(attempt.timestamp)}, {formatTime(attempt.timestamp)}</span>
                          </div>
                        </td>
                        <td>
                          <code class="text-xs font-mono">{attempt.sourceIP}</code>
                        </td>
                        <td class="text-right">
                          <span class="text-xs font-mono text-muted-foreground">{attempt.destPort || '—'}</span>
                        </td>
                        <td class="text-center">
                          <button onclick={() => setAttemptsJailFilter(attempt.jailName)} class="inline-flex">
                            <Badge variant="warning" size="sm">{attempt.jailName || '-'}</Badge>
                          </button>
                        </td>
                        <td class="text-center">
                          <Badge variant={attempt.action === 'blocked' ? 'danger' : 'success'} size="sm">
                            {attempt.action}
                          </Badge>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>

              <!-- Footer -->
              <div class="data-table-footer">
                <Pagination
                  bind:page={attemptsPage}
                  bind:perPage={attemptsPerPage}
                  total={attemptsTotal}
                  onPageChange={loadAttempts}
                />
              </div>
            {/if}
          </div>

        <!-- Jails Tab -->
        {:else if activeTab === 'jails'}
          <!-- Toolbar -->
          <div class="rounded-xl border border-border bg-muted/80 px-4 py-3 mb-4">
            <div class="flex flex-wrap items-center gap-3">
              <span class="text-sm text-muted-foreground">
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
            <EmptyState
              icon="lock"
              title="No Jails Configured"
              description="Create a jail to automatically block malicious IPs"
              large
            >
              <Button onclick={openCreateJail} size="sm" icon="plus">
                Create Jail
              </Button>
            </EmptyState>
          {:else}
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {#each jails as jail}
                <div class="rounded-lg border border-border bg-card {!jail.enabled && 'opacity-50'}">
                  <!-- Header row -->
                  <div class="flex items-center gap-3 px-3 py-2.5 border-b border-border/50">
                    <div class="flex h-7 w-7 items-center justify-center rounded-md {jail.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                      <Icon name={jail.name === 'sshd' ? 'key' : 'shield'} size={14} />
                    </div>
                    <div class="flex-1 min-w-0">
                      <h3 class="font-semibold text-sm text-foreground capitalize truncate">{jail.name}</h3>
                    </div>
                    <!-- Status & Actions grouped -->
                    <div class="flex items-center gap-1">
                      {#if jail.enabled}
                        <Badge variant="success" size="sm">
                          <span class="w-1 h-1 rounded-full bg-current animate-pulse mr-1"></span>
                          On
                        </Badge>
                      {:else}
                        <Badge variant="secondary" size="sm">Off</Badge>
                      {/if}
                      {#if jail.escalateEnabled}
                        <Badge variant="info" size="sm" title="Auto-escalates to /24 when {jail.escalateThreshold}+ IPs blocked">
                          <Icon name="wand" size={10} />
                        </Badge>
                      {/if}
                      <div class="w-px h-4 bg-border mx-1"></div>
                      <div class="kt-btn-group">
                        <Button onclick={() => openEditJail(jail)} variant="outline" size="xs" icon="edit" title="Edit" />
                        <Button onclick={() => confirmDeleteJail(jail)} variant="outline" size="xs" icon="trash" title="Delete" />
                      </div>
                    </div>
                  </div>

                  <!-- Stats row -->
                  <div class="flex items-center px-3 py-2 gap-3">
                    <div class="flex-1 text-center">
                      <div class="text-xl font-bold text-foreground">{jail.currentlyBanned || 0}</div>
                      <div class="text-[10px] text-muted-foreground">Banned</div>
                    </div>
                    <div class="w-px h-8 bg-muted"></div>
                    <div class="flex-1 text-center">
                      <div class="text-xl font-bold text-foreground">{jail.totalBanned || 0}</div>
                      <div class="text-[10px] text-muted-foreground">Total</div>
                    </div>
                  </div>

                  <!-- Config row -->
                  <div class="flex items-center justify-between gap-2 px-3 py-2 bg-muted/50 border-t border-border/50 text-[10px]">
                    <div class="flex items-center gap-2 text-muted-foreground">
                      <span><strong class="text-foreground">{jail.maxRetry}</strong> retry</span>
                      <span>·</span>
                      <span><strong class="text-foreground">{formatBanTime(jail.findTime)}</strong> find</span>
                      <span>·</span>
                      <span><strong class="text-foreground">{formatBanTime(jail.banTime)}</strong> ban</span>
                    </div>
                    <Badge variant="mono" size="sm">{jail.action || 'drop'}</Badge>
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
    <Select
      label="Duration"
      bind:value={blockForm.duration}
      options={[
        { value: '1h', label: '1 hour' },
        { value: '24h', label: '24 hours' },
        { value: '7d', label: '7 days' },
        { value: '30d', label: '30 days' },
        { value: '90d', label: '90 days' },
        { value: 'permanent', label: 'Permanent' }
      ]}
    />
  </div>

  {#snippet footer()}
    <Button onclick={() => showBlockModal = false} variant="secondary">Cancel</Button>
    <Button onclick={blockIP} variant="destructive" icon="ban">Block</Button>
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
        <Input
          label="Current Port"
          value={sshPort}
          prefixIcon="key"
          size="default"
          class="font-mono"
          readonly
          disabled
        />
      </div>
      <div class="flex-1">
        <Input
          label="New Port"
          type="number"
          bind:value={newSSHPort}
          prefixIcon="key"
          size="default"
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
      <Select label="Status" bind:value={jailForm.enabled}>
        <option value={true}>Enabled</option>
        <option value={false}>Disabled</option>
      </Select>
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
      <Select label="Find Time" bind:value={jailForm.findTime}>
        <option value={300}>5 minutes</option>
        <option value={600}>10 minutes</option>
        <option value={1800}>30 minutes</option>
        <option value={3600}>1 hour</option>
        <option value={7200}>2 hours</option>
        <option value={86400}>24 hours</option>
      </Select>
      <Select label="Ban Time" bind:value={jailForm.banTime}>
        <option value={3600}>1 hour</option>
        <option value={86400}>1 day</option>
        <option value={604800}>7 days</option>
        <option value={2592000}>30 days</option>
        <option value={31536000}>1 year</option>
        <option value={-1}>Permanent</option>
      </Select>
    </div>

    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Port"
        bind:value={jailForm.port}
        placeholder="all or specific port"
      />
      <Select label="Action" bind:value={jailForm.action}>
        <option value="drop">Drop</option>
        <option value="reject">Reject</option>
      </Select>
    </div>

    <!-- Auto-Escalation Settings -->
    <div class="border-t border-border pt-4 mt-4">
      <div class="flex items-center justify-between mb-3">
        <div>
          <span class="kt-label mb-0">Auto-Escalation</span>
          <p class="text-xs text-muted-foreground">Automatically block entire /24 range when threshold IPs are blocked</p>
        </div>
        <Checkbox variant="switch" bind:checked={jailForm.escalateEnabled} />
      </div>

      {#if jailForm.escalateEnabled}
        <div class="grid grid-cols-2 gap-4 p-3 bg-muted/50 rounded-lg">
          <Input
            label="IP Threshold"
            type="number"
            bind:value={jailForm.escalateThreshold}
            min="2"
            max="20"
            helperText="Block /24 when this many IPs blocked"
          />
          <Select label="Time Window" bind:value={jailForm.escalateWindow}>
            <option value={1800}>30 minutes</option>
            <option value={3600}>1 hour</option>
            <option value={7200}>2 hours</option>
            <option value={14400}>4 hours</option>
            <option value={86400}>24 hours</option>
          </Select>
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
      <div class="pb-4 border-b border-dashed border-border">
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
      <div class="pb-4 border-b border-dashed border-border">
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
        <Input
          bind:value={customURL}
          placeholder="https://example.com/blocklist.txt"
          prefixIcon="link"
          suffixAddonBtn={{
            icon: "download",
            label: importingSource === 'custom' ? 'Importing...' : 'Import',
            onclick: () => importBlocklist('custom'),
            disabled: !customURL || importingSource === 'custom',
            loading: importingSource === 'custom'
          }}
          onkeydown={(e) => e.key === 'Enter' && customURL && importBlocklist('custom')}
        />
        <p class="text-xs text-muted-foreground mt-2">Supports: plain IP lists, CIDR notation, ipsum format, FireHOL netset</p>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <Button onclick={() => showImportModal = false} variant="secondary">Close</Button>
  {/snippet}
</Modal>

<!-- Block Countries Modal -->
<Modal bind:open={showBlockCountriesModal} title="Block Countries" size="lg">
  <div class="space-y-4">
    <!-- Search and actions -->
    <div class="flex flex-wrap items-center gap-3">
      <Input
        type="search"
        bind:value={countrySearch}
        placeholder="Search countries..."
        prefixIcon="search"
        class="w-48"
      />
      <div class="flex items-center gap-2">
        <button
          onclick={selectAllFilteredCountries}
          class="text-xs text-primary hover:text-primary/80 font-medium"
        >
          Select all{countrySearch ? ' filtered' : ''}
        </button>
        {#if selectedCountries.length > 0}
          <span class="text-dim">|</span>
          <button
            onclick={clearCountrySelection}
            class="text-xs text-muted-foreground hover:text-foreground"
          >
            Clear selection
          </button>
        {/if}
      </div>
      <div class="ml-auto text-sm text-muted-foreground">
        {unblockedCountries.length} available
      </div>
    </div>

    <!-- Countries grouped by continent -->
    <div class="max-h-96 overflow-y-auto border border-border rounded-lg">
      {#if sortedContinents.length > 0}
        <div class="divide-y divide-border">
          {#each sortedContinents as continent}
            <div class="bg-card">
              <!-- Continent header -->
              <button
                onclick={() => toggleContinentSelection(continent)}
                class="w-full flex items-center gap-3 px-3 py-2 bg-muted hover:bg-muted/80 transition-colors sticky top-0 z-10"
              >
                <Checkbox
                  checked={isContinentFullySelected(continent)}
                  indeterminate={isContinentPartiallySelected(continent)}
                  class="pointer-events-none"
                  tabindex="-1"
                />
                <span class="font-medium text-sm text-foreground">{continent}</span>
                <span class="text-xs text-muted-foreground">
                  ({countriesByContinent[continent]?.length || 0} countries)
                </span>
              </button>
              <!-- Countries in continent -->
              <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1 p-2">
                {#each countriesByContinent[continent] || [] as country}
                  <Checkbox
                    checked={selectedCountries.includes(country.code)}
                    onchange={() => toggleCountrySelection(country.code)}
                    class="px-2 py-1.5 rounded-md hover:bg-muted transition-colors {selectedCountries.includes(country.code) ? 'bg-primary/10' : ''}"
                  >
                    <img
                      use:lazyLoad={"https://flagcdn.com/" + country.code.toLowerCase() + ".svg"}
                      width="16"
                      alt={country.code}
                      class="rounded-sm"
                    />
                    <span class="text-xs text-foreground truncate">{country.name}</span>
                  </Checkbox>
                {/each}
              </div>
            </div>
          {/each}
        </div>
      {:else if countrySearch}
        <div class="text-center py-8 text-sm text-muted-foreground">
          No countries match "{countrySearch}"
        </div>
      {:else}
        <div class="text-center py-8 text-sm text-muted-foreground">
          <Icon name="check-circle" size={24} class="mx-auto text-success mb-2" />
          All available countries are blocked
        </div>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={() => { showBlockCountriesModal = false; selectedCountries = []; countrySearch = '' }} variant="secondary">
      Cancel
    </Button>
    <Button
      onclick={blockSelectedCountries}
      icon="ban"
      disabled={selectedCountries.length === 0 || blockingCountries}
    >
      {#if blockingCountries}
        <div class="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin mr-1"></div>
        Blocking...
      {:else}
        Block {selectedCountries.length > 0 ? `${selectedCountries.length} Countries` : 'Countries'}
      {/if}
    </Button>
  {/snippet}
</Modal>

