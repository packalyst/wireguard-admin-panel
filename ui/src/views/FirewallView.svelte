<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, getInitialTab } from '../stores/app.js'
  import { loadState, saveState, createDebouncedSearch, getDefaultPerPage, lazyLoad } from '../stores/helpers.js'
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
  let { loading = $bindable(true) } = $props()

  // Tabs with dynamic badge for blocked count
  const tabs = $derived([
    { id: 'ports', label: 'Ports', icon: 'lock' },
    { id: 'blocked', label: 'Blocked', icon: 'ban', badge: (status?.blockedIPCount || 0) > 0 ? status?.blockedIPCount : undefined },
    { id: 'attempts', label: 'Activity', icon: 'activity' },
    { id: 'jails', label: 'Jails', icon: 'shield' },
    { id: 'countries', label: 'Countries', icon: 'world' }
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
  const savedBlockedState = loadState('firewall_blocked')
  const savedAttemptsState = loadState('firewall_attempts')

  // UI state - read initial tab from URL hash
  let activeTab = $state(getInitialTab('ports', ['ports', 'blocked', 'attempts', 'jails', 'countries']))

  // Blocked tab state
  let blockedPage = $state(savedBlockedState.page || 1)
  let blockedPerPage = $state(savedBlockedState.perPage || getDefaultPerPage())
  let blockedSearch = $state(savedBlockedState.search || '')
  let blockedJailFilter = $state(savedBlockedState.jail || '')
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
      jail: blockedJailFilter
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

  // Country blocking state
  let availableCountries = $state([])
  let blockedCountries = $state([])
  let countryStatus = $state(null)
  let loadingCountries = $state(false)
  let blockingCountries = $state(false)
  let selectedCountries = $state([])
  let countrySearch = $state('')
  let showBlockCountriesModal = $state(false)
  let showCountryActionsMenu = $state(false)
  let refreshingZones = $state(false)

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

  async function loadCountries(showLoading = true) {
    if (showLoading) loadingCountries = true
    try {
      const [avail, blocked, status] = await Promise.all([
        apiGet('/api/geo/countries'),
        apiGet('/api/geo/blocked'),
        apiGet('/api/geo/blocked/status')
      ])
      availableCountries = avail || []
      blockedCountries = blocked?.countries || []
      countryStatus = status || {}
    } catch (e) {
      toast('Failed to load countries: ' + e.message, 'error')
    } finally {
      loadingCountries = false
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
    } else if (section === 'countries') {
      await loadCountries()
    }
  }

  // Tab change handler - called when user clicks a tab
  function handleTabChange(tabId) {
    if (tabId === 'ports') loadPorts()
    else if (tabId === 'blocked') loadBlocked()
    else if (tabId === 'attempts') loadAttempts()
    else if (tabId === 'jails') loadJails()
    else if (tabId === 'countries') loadCountries()
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

  // Country blocking actions
  async function blockSelectedCountries() {
    if (selectedCountries.length === 0) return

    blockingCountries = true
    try {
      const res = await apiPost('/api/geo/blocked', {
        countryCodes: selectedCountries,
        direction: 'inbound'
      })

      if (selectedCountries.length === 1) {
        // Single country response
        if (res.warning) {
          toast(`${res.name} added with warning: ${res.warning}`, 'warning')
        } else {
          toast(`${res.name} blocked (${res.rangeCount?.toLocaleString()} ranges)`, 'success')
        }
      } else {
        // Bulk response
        const totalRanges = res.results?.reduce((sum, r) => sum + (r.rangeCount || 0), 0) || 0
        toast(`${res.count} countries blocked (${totalRanges.toLocaleString()} ranges)`, 'success')
      }

      selectedCountries = []
      countrySearch = ''
      showBlockCountriesModal = false
      await loadCountries(false)
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      blockingCountries = false
    }
  }

  function toggleCountrySelection(code) {
    if (selectedCountries.includes(code)) {
      selectedCountries = selectedCountries.filter(c => c !== code)
    } else {
      selectedCountries = [...selectedCountries, code]
    }
  }

  function selectAllFilteredCountries() {
    const filtered = filteredUnblockedCountries.map(c => c.code)
    selectedCountries = [...new Set([...selectedCountries, ...filtered])]
  }

  function clearCountrySelection() {
    selectedCountries = []
  }

  async function unblockCountry(code) {
    try {
      const res = await apiDelete(`/api/geo/blocked/${code}`)
      if (res.status === 'removing') {
        toast(`Removing ${code}...`, 'info')
        await loadCountries(false)
        // Poll for completion
        pollCountryRemoval(code)
      } else {
        toast(`Country ${code} unblocked`, 'success')
        await loadCountries(false)
      }
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function pollCountryRemoval(code, attempts = 0) {
    if (attempts > 30) return // Stop after 30 seconds
    setTimeout(async () => {
      await loadCountries(false)
      const country = blockedCountries.find(c => c.country_code === code)
      if (country) {
        // Still exists, keep polling
        pollCountryRemoval(code, attempts + 1)
      } else {
        toast(`Country ${code} unblocked`, 'success')
      }
    }, 1000)
  }

  async function toggleCountryDirection(code, currentDirection) {
    const newDirection = currentDirection === 'inbound' ? 'both' : 'inbound'
    try {
      await apiPost('/api/geo/blocked', { countryCode: code, direction: newDirection })
      toast(`${code} direction changed to ${newDirection}`, 'success')
      await loadCountries(false)
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function refreshZones() {
    refreshingZones = true
    try {
      const res = await apiPost('/api/geo/zones/refresh')
      toast(`Refreshed ${res.updated} countries${res.errors > 0 ? ` (${res.errors} errors)` : ''}`, res.errors > 0 ? 'warning' : 'success')
      await loadCountries()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      refreshingZones = false
    }
  }

  // Country flag emoji helper
  function getFlagEmoji(code) {
    if (!code || code.length !== 2) return ''
    const codePoints = code.toUpperCase().split('').map(char => 127397 + char.charCodeAt())
    return String.fromCodePoint(...codePoints)
  }

  // Get country name from config or blocked list
  function getCountryName(code) {
    const blockedArr = blockedCountries || []
    const availArr = availableCountries || []
    const blocked = blockedArr.find?.(c => c.country_code === code)
    if (blocked) return blocked.name
    const avail = availArr.find?.(c => c.code === code)
    if (avail) return avail.name
    return code
  }

  // Countries not yet blocked
  const unblockedCountries = $derived.by(() => {
    const avail = availableCountries || []
    const blocked = blockedCountries || []
    if (!avail.filter || !blocked.some) return []
    return avail.filter(c => !blocked.some(b => b.country_code === c.code))
  })

  // Filtered unblocked countries (for search)
  const filteredUnblockedCountries = $derived.by(() => {
    const countries = unblockedCountries || []
    if (!countries.filter) return []
    const search = countrySearch?.trim() || ''
    if (!search) return countries
    return countries.filter(c =>
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.code.toLowerCase().includes(search.toLowerCase()) ||
      c.continent?.toLowerCase().includes(search.toLowerCase())
    )
  })

  // Group countries by continent
  const continentOrder = ['Africa', 'Asia', 'Europe', 'North America', 'Oceania', 'South America', 'Antarctica']
  const countriesByContinent = $derived.by(() => {
    const countries = filteredUnblockedCountries || []
    const grouped = {}
    for (const c of countries) {
      const continent = c.continent || 'Other'
      if (!grouped[continent]) grouped[continent] = []
      grouped[continent].push(c)
    }
    // Sort countries within each continent
    for (const continent of Object.keys(grouped)) {
      grouped[continent].sort((a, b) => a.name.localeCompare(b.name))
    }
    return grouped
  })

  // Get sorted continents
  const sortedContinents = $derived.by(() => {
    const grouped = countriesByContinent || {}
    return continentOrder.filter(c => grouped[c]?.length > 0)
  })

  // Select/deselect all countries in a continent
  function toggleContinentSelection(continent) {
    const countries = countriesByContinent[continent] || []
    const codes = countries.map(c => c.code)
    const allSelected = codes.every(code => selectedCountries.includes(code))
    if (allSelected) {
      // Deselect all
      selectedCountries = selectedCountries.filter(c => !codes.includes(c))
    } else {
      // Select all
      const newSelection = [...selectedCountries]
      for (const code of codes) {
        if (!newSelection.includes(code)) newSelection.push(code)
      }
      selectedCountries = newSelection
    }
  }

  // Check if all countries in a continent are selected
  function isContinentFullySelected(continent) {
    const countries = countriesByContinent[continent] || []
    if (countries.length === 0) return false
    return countries.every(c => selectedCountries.includes(c.code))
  }

  // Check if some countries in a continent are selected
  function isContinentPartiallySelected(continent) {
    const countries = countriesByContinent[continent] || []
    const selectedCount = countries.filter(c => selectedCountries.includes(c.code)).length
    return selectedCount > 0 && selectedCount < countries.length
  }

  // Helpers
  function formatTimeRemaining(expiresAt) {
    if (!expiresAt || expiresAt.startsWith('0001-')) return 'Permanent'
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
    loadSSHPort() // Load SSH port for the SSH change feature
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
            {status?.enabled ? 'Firewall Active' : 'Firewall Inactive'}
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
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-md bg-warning/10 text-warning">
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
                              class="icon-btn-destructive"
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
          <div class="data-table">
            <!-- Header -->
            <div class="data-table-header">
              <div class="data-table-header-start">
                <Input
                  type="search"
                  value={blockedSearchQuery}
                  oninput={handleBlockedSearchInput}
                  placeholder="Search IP, reason..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
                {#if blockedJails.length > 0}
                  <Select
                    value={blockedJailFilter}
                    onchange={(e) => setBlockedJailFilter(e.target.value)}
                    class="sm:w-40"
                  >
                    <option value="">All jails</option>
                    {#each blockedJails as jail}
                      <option value={jail}>{jail}</option>
                    {/each}
                  </Select>
                {/if}
              </div>
              <div class="data-table-header-end">
                <div class="kt-btn-group">
                  <Button onclick={openImportModal} variant="outline" size="sm" icon="download">
                    Import
                  </Button>
                  <Button onclick={() => showBlockModal = true} size="sm" icon="plus">
                    Block IP
                  </Button>
                </div>
              </div>
            </div>

            <!-- Content -->
            {#if loadingBlocked && blockedIPs.length === 0}
              <div class="data-table-loading">
                <LoadingSpinner size="lg" />
              </div>
            {:else if blockedIPs.length === 0}
              <div class="data-table-empty">
                <EmptyState
                  icon="shield-check"
                  title="No blocked IPs"
                  description={blockedSearch || blockedJailFilter ? 'No results match your filters' : 'IPs will appear here when blocked by the firewall'}
                />
              </div>
            {:else}
              <div class="data-table-content">
                <table>
                  <thead>
                    <tr>
                      <th>Blocked / Source</th>
                      <th>IP / Range</th>
                      <th>Expires</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each blockedIPs as blocked}
                      <tr>
                        <td class="data-table-cell-nowrap">
                          <div class="flex items-center gap-1.5">
                            <Icon name="clock" size={14} class="text-muted-foreground" />
                            <div>
                              <div class="text-xs font-medium">{formatRelativeDate(blocked.blockedAt)}, {formatTime(blocked.blockedAt)}</div>
                              <button onclick={() => setBlockedJailFilter(blocked.jailName)} class="text-[10px] text-muted-foreground hover:text-foreground">
                                {blocked.source || blocked.jailName || 'manual'}
                              </button>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div class="flex items-center gap-2">
                            <Icon name={blocked.isRange ? 'network' : 'globe'} size={14} class="text-muted-foreground" />
                            <code class="text-xs font-mono">{blocked.ip}</code>
                            {#if blocked.isRange}
                              <Badge variant="info" size="sm">Range</Badge>
                            {/if}
                          </div>
                          {#if blocked.reason}
                            <div class="text-[10px] text-muted-foreground mt-0.5 ml-5 truncate max-w-48" title={blocked.reason}>
                              {blocked.reason}
                            </div>
                          {/if}
                          {#if blocked.escalatedFrom}
                            <div class="text-[10px] text-muted-foreground mt-0.5 ml-5">
                              Escalated from {blocked.escalatedFrom}
                            </div>
                          {/if}
                        </td>
                        <td class="data-table-cell-nowrap">
                          {#if blocked.expiresAt}
                            <Badge variant="warning" size="sm">
                              {formatTimeRemaining(blocked.expiresAt)}
                            </Badge>
                          {:else}
                            <Badge variant="danger" size="sm">Permanent</Badge>
                          {/if}
                        </td>
                        <td class="data-table-cell-actions">
                          <button onclick={() => confirmUnblock(blocked)} class="icon-btn" title="Unblock">
                            <Icon name="lock-open" size={14} />
                          </button>
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
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {#each jails as jail}
                <div class="rounded-lg border border-slate-200 bg-white dark:border-zinc-800 dark:bg-zinc-900 {!jail.enabled && 'opacity-50'}">
                  <!-- Header row -->
                  <div class="flex items-center gap-3 px-3 py-2.5 border-b border-slate-100 dark:border-zinc-800">
                    <div class="flex h-7 w-7 items-center justify-center rounded-md {jail.enabled ? 'bg-success/10 text-success' : 'bg-slate-100 text-slate-400 dark:bg-zinc-800 dark:text-zinc-500'}">
                      <Icon name={jail.name === 'sshd' ? 'key' : 'shield'} size={14} />
                    </div>
                    <div class="flex-1 min-w-0">
                      <h3 class="font-semibold text-sm text-slate-900 dark:text-zinc-100 capitalize truncate">{jail.name}</h3>
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
                      <div class="w-px h-4 bg-slate-200 dark:bg-zinc-700 mx-1"></div>
                      <div class="kt-btn-group">
                        <Button onclick={() => openEditJail(jail)} variant="outline" size="xs" icon="edit" title="Edit" />
                        <Button onclick={() => confirmDeleteJail(jail)} variant="outline" size="xs" icon="trash" title="Delete" />
                      </div>
                    </div>
                  </div>

                  <!-- Stats row -->
                  <div class="flex items-center px-3 py-2 gap-3">
                    <div class="flex-1 text-center">
                      <div class="text-xl font-bold text-slate-900 dark:text-zinc-100">{jail.currentlyBanned || 0}</div>
                      <div class="text-[10px] text-slate-400 dark:text-zinc-500">Banned</div>
                    </div>
                    <div class="w-px h-8 bg-slate-100 dark:bg-zinc-800"></div>
                    <div class="flex-1 text-center">
                      <div class="text-xl font-bold text-slate-900 dark:text-zinc-100">{jail.totalBanned || 0}</div>
                      <div class="text-[10px] text-slate-400 dark:text-zinc-500">Total</div>
                    </div>
                  </div>

                  <!-- Config row -->
                  <div class="flex items-center justify-between gap-2 px-3 py-2 bg-slate-50 dark:bg-zinc-800/50 border-t border-slate-100 dark:border-zinc-800 text-[10px]">
                    <div class="flex items-center gap-2 text-slate-500 dark:text-zinc-400">
                      <span><strong class="text-slate-700 dark:text-zinc-300">{jail.maxRetry}</strong> retry</span>
                      <span>·</span>
                      <span><strong class="text-slate-700 dark:text-zinc-300">{formatBanTime(jail.findTime)}</strong> find</span>
                      <span>·</span>
                      <span><strong class="text-slate-700 dark:text-zinc-300">{formatBanTime(jail.banTime)}</strong> ban</span>
                    </div>
                    <Badge variant="mono" size="sm">{jail.action || 'drop'}</Badge>
                  </div>
                </div>
              {/each}
            </div>
          {/if}

        <!-- Countries Tab -->
        {:else if activeTab === 'countries'}
          {#if loadingCountries}
            <div class="flex flex-col items-center justify-center py-8">
              <div class="w-6 h-6 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              <p class="mt-2 text-sm text-muted-foreground">Loading countries...</p>
            </div>
          {:else if countryStatus?.enabled === false}
            <!-- Country blocking disabled -->
            <div class="rounded-xl border border-info/30 bg-info/5 p-6 text-center">
              <div class="flex justify-center mb-4">
                <div class="w-12 h-12 rounded-full bg-info/10 flex items-center justify-center">
                  <Icon name="world-off" size={24} class="text-info" />
                </div>
              </div>
              <h3 class="text-lg font-semibold text-foreground mb-2">Country Blocking Disabled</h3>
              <p class="text-sm text-muted-foreground mb-4">
                Country blocking is currently disabled. Enable it in Settings to block traffic from specific countries.
              </p>
              <a href="/settings" class="kt-btn kt-btn-primary kt-btn-sm">
                <Icon name="settings" size={14} class="mr-1" />
                Go to Settings
              </a>
            </div>
          {:else}
            <div class="space-y-6">
              <!-- Currently Blocked Countries -->
              <div class="rounded-xl border border-slate-200 bg-white overflow-hidden dark:border-zinc-800 dark:bg-zinc-900">
                <!-- Table Header -->
                <div class="px-4 py-3 border-b border-slate-200 dark:border-zinc-700 bg-slate-50 dark:bg-zinc-800/50">
                  <div class="flex items-center justify-between">
                    <div class="flex items-center gap-3">
                      <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
                        <Icon name="shield" size={16} />
                      </div>
                      <div>
                        <h4 class="text-sm font-semibold text-foreground">Blocked Countries</h4>
                        <p class="text-xs text-muted-foreground">
                          {blockedCountries.length} {blockedCountries.length === 1 ? 'country' : 'countries'} · {countryStatus?.total_ranges?.toLocaleString() || 0} IP ranges
                        </p>
                      </div>
                    </div>
                    <div class="flex items-center gap-2">
                      <!-- Desktop buttons -->
                      <div class="hidden sm:flex kt-btn-group">
                        <Button
                          onclick={() => showBlockCountriesModal = true}
                          size="sm"
                          icon="plus"
                          disabled={unblockedCountries.length === 0}
                        >
                          Block Countries
                        </Button>
                        <Button
                          onclick={refreshZones}
                          variant="outline"
                          size="sm"
                          icon={refreshingZones ? undefined : 'refresh'}
                          disabled={refreshingZones || blockedCountries.length === 0}
                        >
                          {#if refreshingZones}
                            <Icon name="refresh" size={14} class="animate-spin" />
                          {/if}
                          {refreshingZones ? 'Refreshing...' : 'Refresh'}
                        </Button>
                      </div>

                      <!-- Mobile dropdown -->
                      <div class="relative sm:hidden">
                        <Button
                          onclick={() => showCountryActionsMenu = !showCountryActionsMenu}
                          variant="outline"
                          size="sm"
                          icon="dots"
                        />
                        {#if showCountryActionsMenu}
                          <div class="kt-dropdown" role="menu">
                            <button
                              onclick={() => { showBlockCountriesModal = true; showCountryActionsMenu = false }}
                              disabled={unblockedCountries.length === 0}
                              class="kt-dropdown-item"
                            >
                              <Icon name="plus" size={14} class="kt-dropdown-item-icon" />
                              Block Countries
                            </button>
                            <div class="kt-dropdown-divider"></div>
                            <button
                              onclick={() => { refreshZones(); showCountryActionsMenu = false }}
                              disabled={refreshingZones || blockedCountries.length === 0}
                              class="kt-dropdown-item"
                            >
                              <Icon name="refresh" size={14} class="kt-dropdown-item-icon {refreshingZones ? 'animate-spin' : ''}" />
                              {refreshingZones ? 'Refreshing...' : 'Refresh Zones'}
                            </button>
                          </div>
                          <button class="kt-dropdown-backdrop" onclick={() => showCountryActionsMenu = false} aria-label="Close menu"></button>
                        {/if}
                      </div>
                    </div>
                  </div>
                </div>

                {#if blockedCountries.length > 0}
                  <div class="overflow-x-auto">
                    <table class="w-full">
                      <thead>
                        <tr class="border-b border-slate-100 dark:border-zinc-800 bg-slate-50/50 dark:bg-zinc-800/30">
                          <th class="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-zinc-400">Country</th>
                          <th class="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-zinc-400">Direction</th>
                          <th class="px-4 py-2.5 text-right text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-zinc-400">IP Ranges</th>
                          <th class="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-zinc-400">Added</th>
                          <th class="px-4 py-2.5 w-12"></th>
                        </tr>
                      </thead>
                      <tbody class="divide-y divide-slate-100 dark:divide-zinc-800">
                        {#each blockedCountries as country}
                          <tr class="group transition-colors {country.status === 'removing' ? 'opacity-50 bg-slate-100 dark:bg-zinc-800' : 'hover:bg-slate-50 dark:hover:bg-zinc-800/50'}">
                            <td class="px-3 py-2">
                              <div class="flex items-center gap-3">
                                <img
                                  src="https://flagcdn.com/{country.country_code.toLowerCase()}.svg"
                                  width="24"
                                  alt={country.country_code}
                                  class="rounded-sm shadow-sm"
                                  loading="lazy"
                                />
                                <div class="font-medium text-slate-900 dark:text-zinc-100">
                                  {country.name}<sup class="ml-1 text-[10px] text-slate-400 dark:text-zinc-500 font-mono">{country.country_code}</sup>
                                </div>
                                {#if country.status === 'removing'}
                                  <Badge variant="warning" size="sm">
                                    <Icon name="refresh" size={10} class="mr-1 animate-spin" />
                                    Removing...
                                  </Badge>
                                {/if}
                              </div>
                            </td>
                            <td class="px-3 py-2">
                              <button
                                onclick={() => toggleCountryDirection(country.country_code, country.direction || 'inbound')}
                                class="cursor-pointer hover:opacity-80 transition-opacity"
                                disabled={country.status === 'removing'}
                                data-kt-tooltip
                              >
                                <Badge variant={country.direction === 'both' ? 'warning' : 'secondary'} size="sm">
                                  {#if country.direction === 'both'}
                                    <Icon name="arrow-left" size={10} class="mr-0.5" />
                                    <Icon name="arrow-right" size={10} class="mr-1" />
                                    Both
                                  {:else}
                                    <Icon name="arrow-left" size={10} class="mr-1" />
                                    Inbound
                                  {/if}
                                </Badge>
                                <span data-kt-tooltip-content class="kt-tooltip hidden">Click to toggle direction</span>
                              </button>
                            </td>
                            <td class="px-3 py-2 text-right">
                              <Badge variant="secondary" size="sm">
                                <Icon name="network" size={12} class="mr-1" />
                                {country.range_count?.toLocaleString() || '0'}
                              </Badge>
                            </td>
                            <td class="px-3 py-2">
                              <Badge variant="secondary" size="sm">
                                <Icon name="clock" size={12} class="mr-1" />
                                {timeAgo(country.created_at)}
                              </Badge>
                            </td>
                            <td class="px-3 py-2">
                              {#if country.status === 'removing'}
                                <div class="w-4 h-4 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
                              {:else}
                                <button
                                  onclick={() => unblockCountry(country.country_code)}
                                  class="custom_btns"
                                  data-kt-tooltip
                                >
                                  <Icon name="lock-open" size={16} />
                                  <span data-kt-tooltip-content class="kt-tooltip hidden">Unblock country</span>
                                </button>
                              {/if}
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {:else}
                  <div class="flex flex-col items-center justify-center py-12 text-center">
                    <div class="flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-400 dark:bg-zinc-800 dark:text-zinc-500">
                      <Icon name="world" size={24} />
                    </div>
                    <h4 class="mt-4 text-sm font-medium text-slate-600 dark:text-zinc-300">No countries blocked</h4>
                    <p class="mt-1 text-xs text-slate-400 dark:text-zinc-500">Select countries above to block traffic</p>
                  </div>
                {/if}
              </div>
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
          <span class="text-slate-300 dark:text-zinc-600">|</span>
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
    <div class="max-h-96 overflow-y-auto border border-slate-200 dark:border-zinc-700 rounded-lg">
      {#if sortedContinents.length > 0}
        <div class="divide-y divide-slate-200 dark:divide-zinc-700">
          {#each sortedContinents as continent}
            <div class="bg-white dark:bg-zinc-900">
              <!-- Continent header -->
              <button
                onclick={() => toggleContinentSelection(continent)}
                class="w-full flex items-center gap-3 px-3 py-2 bg-slate-50 dark:bg-zinc-800 hover:bg-slate-100 dark:hover:bg-zinc-700 transition-colors sticky top-0 z-10"
              >
                <input
                  type="checkbox"
                  checked={isContinentFullySelected(continent)}
                  indeterminate={isContinentPartiallySelected(continent)}
                  class="w-4 h-4 rounded border-slate-300 text-primary focus:ring-primary/20 dark:border-zinc-600 dark:bg-zinc-700 pointer-events-none"
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
                  <label
                    class="flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer hover:bg-slate-50 dark:hover:bg-zinc-800 transition-colors {selectedCountries.includes(country.code) ? 'bg-primary/5 dark:bg-primary/10' : ''}"
                  >
                    <input
                      type="checkbox"
                      checked={selectedCountries.includes(country.code)}
                      onchange={() => toggleCountrySelection(country.code)}
                      class="w-3.5 h-3.5 rounded border-slate-300 text-primary focus:ring-primary/20 dark:border-zinc-600 dark:bg-zinc-700"
                    />
                    <img
                      use:lazyLoad={"https://flagcdn.com/" + country.code.toLowerCase() + ".svg"}
                      width="16"
                      alt={country.code}
                      class="rounded-sm"
                    />
                    <span class="text-xs text-slate-700 dark:text-zinc-300 truncate">{country.name}</span>
                  </label>
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

