<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, apiGetText, apiGetBlob } from '../stores/app.js'
  import { formatDate, timeAgo } from '$lib/utils/format.js'
  import { copyToClipboard as copyText } from '$lib/utils/clipboard.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'

  let { loading = $bindable(true) } = $props()

  // VPN Router state (minimal - for Access tab visibility)
  let routerRunning = $state(false)

  // ACL state
  let vpnClients = $state([])
  let selectedVpnClient = $state(null)
  let aclPolicy = $state('selected')
  let allowedClientIds = $state([])
  let bidirectionalMap = $state({}) // targetId -> boolean
  let aclLoading = $state(false)
  let aclSyncing = $state(false)
  let hasDNS = $state(false)

  let routes = $state([])
  let pollInterval = null

  async function loadData() {
    try {
      const [clientsRes, routesRes] = await Promise.all([
        apiGet('/api/vpn/clients'),
        apiGet('/api/hs/routes')
      ])
      vpnClients = Array.isArray(clientsRes) ? clientsRes : []
      routes = routesRes.routes || []
    } catch (e) {
      toast('Failed to load nodes: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  async function checkRouterStatus() {
    try {
      const status = await apiGet('/api/vpn/router/status')
      routerRunning = status?.status === 'running'
    } catch (e) {
      routerRunning = false
    }
  }

  // ACL functions - sync now happens automatically on loadData via /api/vpn/clients
  async function syncVpnClients() {
    aclSyncing = true
    try {
      await loadData()
      toast('VPN clients synced', 'success')
    } catch (e) {
      toast('Failed to sync clients: ' + e.message, 'error')
    } finally {
      aclSyncing = false
    }
  }

  async function loadVpnClientByIp(ip) {
    if (!ip) return null
    // Find VPN client that matches this IP
    const client = vpnClients.find(c => c.ip === ip)
    if (!client) return null

    try {
      const data = await apiGet(`/api/vpn/clients/${client.id}`)
      selectedVpnClient = data.client
      aclPolicy = data.client.aclPolicy || 'selected'
      allowedClientIds = (data.rules || []).map(r => r.targetClientId)
      hasDNS = data.hasDNS || false
      // Build bidirectional map from API response
      const biMap = {}
      for (const rule of (data.rules || [])) {
        biMap[rule.targetClientId] = rule.isBidirectional || false
      }
      bidirectionalMap = biMap
      return data.client
    } catch (e) {
      return null
    }
  }

  async function saveAcl() {
    if (!selectedVpnClient) return
    aclLoading = true
    try {
      await apiPut(`/api/vpn/clients/${selectedVpnClient.id}/acl`, {
        policy: aclPolicy,
        allowedClientIds: allowedClientIds,
        bidirectional: bidirectionalMap
      })
      // Auto-apply rules after saving
      await apiPost('/api/vpn/apply')
      toast('Access rules saved and applied', 'success')
      // Reload data to refresh client list and ACL states
      await loadData()
      // Reload current client's ACL data
      if (selectedNode?._ip) {
        await loadVpnClientByIp(selectedNode._ip)
      }
    } catch (e) {
      toast('Failed to save access rules: ' + e.message, 'error')
    } finally {
      aclLoading = false
    }
  }

  async function toggleDNS() {
    if (!selectedVpnClient) return
    try {
      await apiPut(`/api/vpn/clients/${selectedVpnClient.id}/dns`, { enabled: !hasDNS })
      hasDNS = !hasDNS
      toast(hasDNS ? 'DNS enabled' : 'DNS disabled', 'success')
    } catch (e) {
      toast('Failed to toggle DNS: ' + e.message, 'error')
    }
  }

  function toggleAllowedClient(clientId) {
    if (allowedClientIds.includes(clientId)) {
      allowedClientIds = allowedClientIds.filter(id => id !== clientId)
      // Also remove from bidirectional map
      const newMap = { ...bidirectionalMap }
      delete newMap[clientId]
      bidirectionalMap = newMap
    } else {
      allowedClientIds = [...allowedClientIds, clientId]
    }
  }

  function toggleBidirectional(clientId) {
    bidirectionalMap = { ...bidirectionalMap, [clientId]: !bidirectionalMap[clientId] }
  }

  onMount(() => {
    loadData()
    checkRouterStatus()
    pollInterval = setInterval(() => {
      loadData()
      checkRouterStatus()
    }, 30000)
  })

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval)
  })

  // Load saved filters from localStorage
  const savedFilters = typeof localStorage !== 'undefined' ? JSON.parse(localStorage.getItem('nodes') || '{}') : {}

  let search = $state('')
  let statusFilter = $state(savedFilters.status || 'all') // 'all' | 'online' | 'offline'
  let typeFilter = $state(savedFilters.type || 'all') // 'all' | 'tailscale' | 'wireguard'
  let showFiltersDropdown = $state(false)
  let selectedNode = $state(null)

  // Save filters to localStorage when they change
  $effect(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('nodes', JSON.stringify({ status: statusFilter, type: typeFilter }))
    }
  })
  let activeTab = $state('overview')
  let showCreateModal = $state(false)
  let showNodeModal = $state(false)

  // Handle node modal close - reset editing states
  $effect(() => {
    if (!showNodeModal) {
      selectedNode = null
      editingName = false
      editingTags = false
    }
  })

  function openNodeModal(node) {
    selectedNode = node
    showNodeModal = true
  }

  let newPeerName = $state('')
  let createdPeer = $state(null)
  let tunnelMode = $state('full') // 'full' or 'split'

  // Inline editing states
  let editingName = $state(false)
  let editingTags = $state(false)
  let newName = $state('')
  let newTags = $state('')

  // QR code - fetch with auth
  let qrUrl = $state(null)
  let qrLoading = $state(false)

  // Delete/expire confirmation
  let confirmAction = $state(null) // 'delete' | 'expire' | null
  let actionLoading = $state(false)

  async function loadQrCode(peerId, mode) {
    qrLoading = true
    qrUrl = null
    try {
      const blob = await apiGetBlob(`/api/wg/peers/${peerId}/qr?mode=${mode}`)
      qrUrl = URL.createObjectURL(blob)
    } catch (e) {
      toast('Failed to load QR code', 'error')
    } finally {
      qrLoading = false
    }
  }

  // Load QR when tab changes to 'qr' for wireguard peer
  $effect(() => {
    if (selectedNode?._type === 'wireguard' && activeTab === 'qr') {
      loadQrCode(selectedNode._wgId, tunnelMode)
    }
  })

  // Build unified node list from vpnClients (which contains rawData with full info)
  const allNodes = $derived(vpnClients.map(client => {
    const raw = client.rawData || {}

    if (client.type === 'wireguard') {
      return {
        id: `wg-${client.externalId}`,
        _wgId: client.externalId,
        _type: 'wireguard',
        _displayName: client.name,
        _ip: client.ip,
        _online: raw.online || false,
        online: raw.online || false,
        lastHandshake: raw.lastHandshake,
        name: client.name,
        givenName: client.name,
        ipAddresses: [client.ip],
        createdAt: raw.createdAt || client.createdAt,
        lastSeen: raw.lastSeen,
        user: { name: 'WireGuard' },
        enabled: raw.enabled !== false,
        publicKey: raw.publicKey,
        privateKey: raw.privateKey,
        presharedKey: raw.presharedKey
      }
    } else {
      // Headscale node
      return {
        ...raw,
        id: client.externalId,
        _type: 'tailscale',
        _displayName: raw.givenName || raw.name || client.name,
        _ip: client.ip,
        _online: raw.online || false,
        ipAddresses: raw.ipAddresses || [client.ip],
        user: raw.user || { name: 'Unknown' }
      }
    }
  }))

  const filteredNodes = $derived(allNodes.filter(n => {
    // Status filter
    if (statusFilter === 'online' && !n._online) return false
    if (statusFilter === 'offline' && n._online) return false

    // Type filter
    if (typeFilter === 'tailscale' && n._type !== 'tailscale') return false
    if (typeFilter === 'wireguard' && n._type !== 'wireguard') return false

    // Search filter
    if (!search) return true
    const q = search.toLowerCase()
    return (
      n.name?.toLowerCase().includes(q) ||
      n.givenName?.toLowerCase().includes(q) ||
      n._displayName?.toLowerCase().includes(q) ||
      n._ip?.includes(q) ||
      n.user?.name?.toLowerCase().includes(q) ||
      n._type?.toLowerCase().includes(q)
    )
  }))

  // Get routes for selected node
  const nodeRoutes = $derived(selectedNode && selectedNode._type === 'tailscale'
    ? routes.filter(r => r.node?.id === selectedNode.id)
    : [])
  const isExitNode = $derived(nodeRoutes.some(r => r.prefix === '0.0.0.0/0'))

  function getDeviceIcon(node) {
    if (node._type === 'wireguard') return 'lock'
    const lower = node.name?.toLowerCase() || ''
    if (lower.includes('iphone') || lower.includes('android') || lower.includes('pixel')) return 'device-mobile'
    if (lower.includes('ipad') || lower.includes('tablet')) return 'device-tablet'
    if (lower.includes('macbook') || lower.includes('laptop')) return 'device-laptop'
    return 'device-desktop'
  }

  function selectNode(node) {
    selectedNode = node
    activeTab = 'overview'
    editingName = false
    editingTags = false
    tunnelMode = 'full'
    newName = node._displayName
    newTags = (node.forcedTags || []).map(t => t.replace('tag:', '')).join(', ')
    // Reset ACL state
    selectedVpnClient = null
    aclPolicy = 'selected'
    allowedClientIds = []
    bidirectionalMap = {}
    hasDNS = false
    showNodeModal = true
    // Load VPN client for DNS toggle
    loadVpnClientByIp(node._ip)
  }

  // Load VPN client when switching to 'access' tab
  $effect(() => {
    if (activeTab === 'access' && selectedNode && !selectedVpnClient) {
      loadVpnClientByIp(selectedNode._ip)
    }
  })

  function closeModal() {
    showNodeModal = false
    confirmAction = null
  }

  async function saveName() {
    if (!selectedNode || !newName.trim()) return
    try {
      if (selectedNode._type === 'wireguard') {
        await apiPut(`/api/wg/peers/${selectedNode._wgId}`, { name: newName })
      } else {
        await apiPost(`/api/hs/nodes/${selectedNode.id}/rename/${encodeURIComponent(newName)}`)
      }
      toast('Node renamed', 'success')
      editingName = false
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function saveTags() {
    if (!selectedNode) return
    try {
      const tags = newTags.split(',').map(t => t.trim()).filter(Boolean).map(t => t.startsWith('tag:') ? t : `tag:${t}`)
      await apiPut(`/api/hs/nodes/${selectedNode.id}/tags`, { tags })
      toast('Tags updated', 'success')
      editingTags = false
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function deleteNode() {
    if (!selectedNode) return
    actionLoading = true
    try {
      if (selectedNode._type === 'wireguard') {
        await apiDelete(`/api/wg/peers/${selectedNode._wgId}`)
      } else {
        await apiDelete(`/api/hs/nodes/${selectedNode.id}`)
      }
      toast('Node deleted', 'success')
      closeModal()
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      actionLoading = false
      confirmAction = null
    }
  }

  async function expireNode() {
    if (!selectedNode) return
    actionLoading = true
    try {
      await apiPost(`/api/hs/nodes/${selectedNode.id}/expire`)
      toast('Node key expired', 'success')
      confirmAction = null
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      actionLoading = false
    }
  }

  async function toggleWgPeer() {
    if (!selectedNode) return
    try {
      const newState = !selectedNode.enabled
      await apiPost(`/api/wg/peers/${selectedNode._wgId}/${selectedNode.enabled ? 'disable' : 'enable'}`)
      toast(newState ? 'Peer enabled' : 'Peer disabled', 'success')
      // Update selectedNode immediately for UI feedback
      selectedNode = { ...selectedNode, enabled: newState }
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function createWgPeer() {
    if (!newPeerName.trim()) return
    try {
      const data = await apiPost('/api/wg/peers', { name: newPeerName })
      createdPeer = data
      toast('Peer created', 'success')
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function downloadConfig() {
    if (!selectedNode) return
    try {
      const config = await apiGetText(`/api/wg/peers/${selectedNode._wgId}/config?mode=${tunnelMode}`)
      const blob = new Blob([config], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${selectedNode._displayName}.conf`
      a.click()
      URL.revokeObjectURL(url)
      toast('Configuration downloaded', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function copyConfig() {
    if (!selectedNode) return
    try {
      const config = await apiGetText(`/api/wg/peers/${selectedNode._wgId}/config?mode=${tunnelMode}`)
      await navigator.clipboard.writeText(config)
      toast('Configuration copied', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function copyToClipboard(text) {
    const success = await copyText(text)
    toast(success ? 'Copied!' : 'Failed to copy', success ? 'success' : 'error')
  }
</script>

<div class="space-y-4">
  <!-- Toolbar -->
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="server" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Network Nodes</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Manage all connected devices in your mesh network. Includes both Tailscale/Headscale nodes
          and standalone WireGuard peers. Monitor status, configure routes, and control access.
        </p>
      </div>
    </div>
  </div>

  <Toolbar bind:search placeholder="Search nodes by name, IP or user...">
    <!-- Mobile: Filter dropdown button -->
    <div class="relative sm:hidden">
      <span
        onclick={() => showFiltersDropdown = !showFiltersDropdown}
        class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
      >
        <Icon name="filter" size={14} />
        Filters
        {#if statusFilter !== 'all' || typeFilter !== 'all'}
          <span class="kt-badge kt-badge-xs kt-badge-primary">{(statusFilter !== 'all' ? 1 : 0) + (typeFilter !== 'all' ? 1 : 0)}</span>
        {/if}
      </span>

      {#if showFiltersDropdown}
        <div class="absolute right-0 top-full z-20 mt-2 w-48 rounded-lg border border-slate-200 bg-white p-2 shadow-lg dark:border-zinc-700 dark:bg-zinc-900">
          <div class="mb-2 text-[10px] font-medium uppercase text-slate-400 dark:text-zinc-500">Status</div>
          <span onclick={() => { statusFilter = 'all'; typeFilter = 'all' }} class="kt-badge kt-badge-outline {statusFilter === 'all' && typeFilter === 'all' ? 'kt-badge-primary' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer">All ({allNodes.length})</span>
          <span onclick={() => statusFilter = 'online'} class="kt-badge kt-badge-outline {statusFilter === 'online' ? 'kt-badge-success' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer">Online</span>
          <span onclick={() => statusFilter = 'offline'} class="kt-badge kt-badge-outline {statusFilter === 'offline' ? 'kt-badge-warning' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer">Offline</span>

          <div class="my-2 border-t border-slate-200 dark:border-zinc-700"></div>
          <div class="mb-2 text-[10px] font-medium uppercase text-slate-400 dark:text-zinc-500">Type</div>
          <span onclick={() => typeFilter = 'tailscale'} class="kt-badge kt-badge-outline {typeFilter === 'tailscale' ? 'kt-badge-info' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer"><Icon name="cloud" size={12} /> Tailscale ({vpnClients.filter(c => c.type === 'headscale').length})</span>
          <span onclick={() => typeFilter = 'wireguard'} class="kt-badge kt-badge-outline {typeFilter === 'wireguard' ? 'kt-badge-success' : 'kt-badge-secondary'} w-full justify-center cursor-pointer"><Icon name="shield" size={12} /> WireGuard ({vpnClients.filter(c => c.type === 'wireguard').length})</span>
        </div>
      {/if}
    </div>

    <!-- Desktop: Filter badges -->
    <div class="hidden flex-wrap items-center gap-2 sm:flex">
      <!-- All / Reset -->
      <span
        onclick={() => { statusFilter = 'all'; typeFilter = 'all' }}
        class="kt-badge kt-badge-outline {statusFilter === 'all' && typeFilter === 'all' ? 'kt-badge-primary' : 'kt-badge-secondary'} cursor-pointer"
      >
        All
        <span class="kt-badge kt-badge-xs kt-badge-primary">{allNodes.length}</span>
      </span>

      <!-- Status filters -->
      <span
        onclick={() => statusFilter = statusFilter === 'online' ? 'all' : 'online'}
        class="kt-badge kt-badge-outline {statusFilter === 'online' ? 'kt-badge-success' : 'kt-badge-secondary'} cursor-pointer"
      >
        Online
      </span>
      <span
        onclick={() => statusFilter = statusFilter === 'offline' ? 'all' : 'offline'}
        class="kt-badge kt-badge-outline {statusFilter === 'offline' ? 'kt-badge-warning' : 'kt-badge-secondary'} cursor-pointer"
      >
        Offline
      </span>

      <span class="mx-1 h-4 w-px bg-slate-200 dark:bg-zinc-700"></span>

      <!-- Type filters -->
      <span
        onclick={() => typeFilter = typeFilter === 'tailscale' ? 'all' : 'tailscale'}
        class="kt-badge kt-badge-outline {typeFilter === 'tailscale' ? 'kt-badge-info' : 'kt-badge-secondary'} cursor-pointer"
      >
        <Icon name="cloud" size={14} />
        Tailscale
        <span class="kt-badge kt-badge-xs kt-badge-info">{vpnClients.filter(c => c.type === 'headscale').length}</span>
      </span>
      <span
        onclick={() => typeFilter = typeFilter === 'wireguard' ? 'all' : 'wireguard'}
        class="kt-badge kt-badge-outline {typeFilter === 'wireguard' ? 'kt-badge-success' : 'kt-badge-secondary'} cursor-pointer"
      >
        <Icon name="shield" size={14} />
        WireGuard
        <span class="kt-badge kt-badge-xs kt-badge-success">{vpnClients.filter(c => c.type === 'wireguard').length}</span>
      </span>
    </div>
  </Toolbar>

  <!-- Nodes grid -->
  <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
    {#each filteredNodes as node (node.id)}
      {@const isKeyExpired = node._type === 'tailscale' && node.expiry && !node.expiry.startsWith('0001') && new Date(node.expiry) < new Date()}
      <article
        onclick={() => selectNode(node)}
        class="group flex cursor-pointer flex-col rounded-lg border shadow-sm transition hover:shadow-md
          {node._online
            ? 'border-emerald-200/70 bg-white dark:border-emerald-700/50 dark:bg-zinc-900'
            : 'border-slate-200 bg-white dark:border-zinc-800 dark:bg-zinc-900'}"
      >
        <!-- Header: Icon + Name + Status -->
        <div class="flex items-center gap-2.5 p-3">
          <!-- Device icon -->
          <div class="flex h-9 w-9 items-center justify-center rounded-lg shrink-0
            {node._online
              ? 'bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400'
              : 'bg-slate-100 text-slate-500 dark:bg-zinc-800 dark:text-zinc-400'}">
            <Icon name={getDeviceIcon(node)} size={18} />
          </div>

          <!-- Name -->
          <div class="flex-1 min-w-0">
            <h2 class="truncate text-sm font-semibold text-slate-900 dark:text-zinc-100">{node._displayName}</h2>
            <div class="flex items-center gap-1 mt-0.5 text-[11px] text-slate-500 dark:text-zinc-500">
              <Icon name="user" size={11} class="shrink-0" />
              <span class="truncate">{node.user?.name || 'Unassigned'}</span>
            </div>
          </div>

          <!-- Status indicator -->
          <div class="flex flex-col items-end gap-1 shrink-0">
            <span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium
              {node._online
                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300'
                : 'bg-slate-100 text-slate-500 dark:bg-zinc-800 dark:text-zinc-400'}">
              <span class="h-1.5 w-1.5 rounded-full {node._online ? 'bg-emerald-500' : 'bg-slate-400 dark:bg-zinc-500'}"></span>
              {node._online ? 'Online' : 'Offline'}
            </span>
            {#if isKeyExpired}
              <span class="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300">
                Key Expired
              </span>
            {:else if node._type === 'wireguard' && !node.enabled}
              <span class="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300">
                Disabled
              </span>
            {/if}
          </div>
        </div>

        <!-- Info grid: 2 columns -->
        <div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t border-slate-100 dark:border-zinc-800 px-3 py-2.5 text-[11px]">
          <!-- IP -->
          <div class="flex items-center gap-1.5">
            <Icon name="network" size={12} class="text-slate-400 dark:text-zinc-600 shrink-0" />
            <code class="text-slate-700 dark:text-zinc-300 font-mono truncate">{node._ip || '—'}</code>
          </div>
          <!-- Type -->
          <div class="flex items-center gap-1.5">
            <Icon name={node._type === 'wireguard' ? 'shield' : 'cloud'} size={12} class="text-slate-400 dark:text-zinc-600 shrink-0" />
            <span class="text-slate-600 dark:text-zinc-400">{node._type === 'wireguard' ? 'WireGuard' : 'Tailscale'}</span>
          </div>
          <!-- Last seen -->
          <div class="flex items-center gap-1.5">
            <Icon name="clock" size={12} class="text-slate-400 dark:text-zinc-600 shrink-0" />
            <span class="text-slate-500 dark:text-zinc-500 truncate">{timeAgo(node.lastHandshake || node.lastSeen)}</span>
          </div>
          <!-- Key expiry or enabled status -->
          {#if node._type === 'tailscale' && node.expiry && !node.expiry.startsWith('0001')}
            <div class="flex items-center gap-1.5">
              <Icon name="key" size={12} class="{isKeyExpired ? 'text-red-500' : 'text-slate-400 dark:text-zinc-600'} shrink-0" />
              <span class="{isKeyExpired ? 'text-red-600 dark:text-red-400' : 'text-slate-500 dark:text-zinc-500'} truncate">
                {isKeyExpired ? 'Expired' : timeAgo(node.expiry)}
              </span>
            </div>
          {:else if node._type === 'wireguard'}
            <div class="flex items-center gap-1.5">
              <Icon name={node.enabled ? 'check' : 'ban'} size={12} class="{node.enabled ? 'text-emerald-500' : 'text-amber-500'} shrink-0" />
              <span class="{node.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}">
                {node.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          {:else}
            <div></div>
          {/if}
        </div>

        <!-- Tags footer -->
        <div class="flex flex-wrap gap-1 border-t border-slate-100 dark:border-zinc-800 px-3 py-2 min-h-[32px]">
          {#if node._type === 'tailscale' && (node.forcedTags?.length || node.validTags?.length)}
            {#each [...(node.forcedTags || []), ...(node.validTags || [])].slice(0, 3) as tag}
              <span class="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:bg-zinc-800 dark:text-zinc-400">
                {tag.replace('tag:', '')}
              </span>
            {/each}
            {#if [...(node.forcedTags || []), ...(node.validTags || [])].length > 3}
              <span class="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 dark:bg-zinc-800 dark:text-zinc-500">
                +{[...(node.forcedTags || []), ...(node.validTags || [])].length - 3}
              </span>
            {/if}
          {:else}
            <span class="text-[10px] text-slate-400 dark:text-zinc-600">No tags</span>
          {/if}
        </div>
      </article>
    {/each}

    <!-- Add node card -->
    {#if filteredNodes.length > 0}
      <article
        onclick={() => { showCreateModal = true; newPeerName = ''; createdPeer = null }}
        class="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-slate-300 bg-slate-50 p-4 text-center text-xs text-slate-500 transition hover:border-slate-400 hover:bg-slate-100 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:bg-zinc-800/70"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200/80 text-slate-600 dark:bg-zinc-700 dark:text-zinc-100">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-slate-700 dark:text-zinc-100">Add your next node</div>
        <p class="max-w-[200px] text-slate-400 dark:text-zinc-500">
          Create new WireGuard peers or connect Tailscale devices
        </p>
      </article>
    {/if}
  </div>

  {#if filteredNodes.length === 0}
    <div class="mt-4 flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-slate-50 py-16 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
      <div class="flex h-12 w-12 items-center justify-center rounded-full bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-300">
        <Icon name="server" size={24} />
      </div>
      <h4 class="mt-4 text-base font-medium text-slate-700 dark:text-zinc-200">No nodes found</h4>
      <p class="mt-1 text-sm text-slate-500 dark:text-zinc-400">
        {search ? 'Try a different search term' : 'Add a device using the button below'}
      </p>
      {#if !search}
        <Button onclick={() => { showCreateModal = true; newPeerName = ''; createdPeer = null }} size="sm" icon="plus" class="mt-4">
          Add Node
        </Button>
      {/if}
    </div>
  {/if}
</div>

<!-- Node Detail Modal -->
<Modal bind:open={showNodeModal} size="lg" bodyClass="p-0">
  {#snippet header()}
    {#if selectedNode}
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl flex items-center justify-center {selectedNode._online ? 'bg-success/15 text-success' : 'bg-muted text-muted-foreground'}">
          <Icon name={getDeviceIcon(selectedNode)} size={20} />
        </div>
        <div class="flex-1 min-w-0">
          {#if editingName}
            <div class="flex items-center gap-2">
              <Input bind:value={newName} class="py-1 text-base font-semibold" onkeydown={(e) => e.key === 'Enter' && saveName()} />
              <button onclick={saveName} class="p-1 text-success hover:bg-success/10 rounded"><Icon name="check" size={16} /></button>
              <button onclick={() => editingName = false} class="p-1 text-muted-foreground hover:bg-accent rounded"><Icon name="x" size={16} /></button>
            </div>
          {:else}
            <div class="flex items-center gap-2">
              <h2 class="text-base font-semibold text-foreground truncate">{selectedNode._displayName}</h2>
              <button onclick={() => editingName = true} class="p-1 text-muted-foreground hover:text-foreground hover:bg-accent rounded shrink-0">
                <Icon name="edit" size={12} />
              </button>
            </div>
          {/if}
          <div class="flex items-center gap-2 mt-0.5">
            <Badge variant={selectedNode._online ? 'success' : 'muted'} size="sm">{selectedNode._online ? 'Online' : 'Offline'}</Badge>
            <Badge variant={selectedNode._type === 'wireguard' ? 'info' : 'primary'} size="sm">{selectedNode._type === 'wireguard' ? 'WG' : 'TS'}</Badge>
            {#if selectedNode._type === 'wireguard' && !selectedNode.enabled}<Badge variant="warning" size="sm">Disabled</Badge>{/if}
            {#if isExitNode}<Badge variant="success" size="sm">Exit</Badge>{/if}
            <button onclick={toggleDNS} class="kt-badge kt-badge-sm {hasDNS ? 'kt-badge-info' : 'kt-badge-outline kt-badge-secondary'} cursor-pointer" title="Toggle DNS rewrite">DNS</button>
          </div>
        </div>
      </div>
    {/if}
  {/snippet}
  {#if selectedNode}
      <!-- Tabs -->
      <div class="flex border-b border-border px-4 bg-muted/30">
        {#if selectedNode._type === 'wireguard'}
          {#each [{id:'overview',label:'Overview'},{id:'qr',label:'QR & Config'},...(routerRunning ? [{id:'access',label:'Access'}] : []),{id:'actions',label:'Actions'}] as tab}
            <button
              onclick={() => activeTab = tab.id}
              class="px-3 py-2.5 text-xs font-medium border-b-2 -mb-px transition-colors
                {activeTab === tab.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
            >{tab.label}</button>
          {/each}
        {:else}
          {#each [{id:'overview',label:'Overview'},{id:'network',label:'Network'},...(routerRunning ? [{id:'access',label:'Access'}] : []),{id:'security',label:'Actions'}] as tab}
            <button
              onclick={() => activeTab = tab.id}
              class="px-3 py-2.5 text-xs font-medium border-b-2 -mb-px transition-colors
                {activeTab === tab.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
            >{tab.label}</button>
          {/each}
        {/if}
      </div>

      <!-- Content -->
      <div class="p-4 max-h-[60vh] overflow-y-auto">
        {#if activeTab === 'overview'}
          <!-- Info Grid -->
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div class="p-3 bg-muted/50 rounded-lg">
              <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">IP Address</div>
              <div class="flex items-center gap-1">
                <code class="text-sm font-mono text-foreground truncate">{selectedNode._ip || '—'}</code>
                {#if selectedNode._ip}
                  <button onclick={() => copyToClipboard(selectedNode._ip)} class="p-0.5 text-muted-foreground hover:text-foreground shrink-0"><Icon name="copy" size={12} /></button>
                {/if}
              </div>
            </div>
            <div class="p-3 bg-muted/50 rounded-lg">
              <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Created</div>
              <div class="text-sm text-foreground">{formatDate(selectedNode.createdAt)}</div>
            </div>
            <div class="p-3 bg-muted/50 rounded-lg">
              <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Last Seen</div>
              <div class="text-sm text-foreground">{timeAgo(selectedNode.lastHandshake || selectedNode.lastSeen)}</div>
            </div>
            {#if selectedNode._type === 'wireguard'}
              <div class="p-3 bg-muted/50 rounded-lg col-span-2 sm:col-span-3">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Public Key</div>
                <div class="flex items-center gap-1">
                  <code class="text-xs font-mono text-foreground truncate">{selectedNode.publicKey}</code>
                  <button onclick={() => copyToClipboard(selectedNode.publicKey)} class="p-0.5 text-muted-foreground hover:text-foreground shrink-0"><Icon name="copy" size={12} /></button>
                </div>
              </div>
            {:else}
              <div class="p-3 bg-muted/50 rounded-lg">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">User</div>
                <div class="text-sm text-foreground">{selectedNode.user?.name || '—'}</div>
              </div>
              <div class="p-3 bg-muted/50 rounded-lg">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Key Expiry</div>
                <div class="text-sm text-foreground">{selectedNode.expiry && !selectedNode.expiry.startsWith('0001') ? formatDate(selectedNode.expiry) : 'Never'}</div>
              </div>
              {#if selectedNode.ipAddresses?.[1]}
                <div class="p-3 bg-muted/50 rounded-lg">
                  <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">IPv6</div>
                  <div class="flex items-center gap-1">
                    <code class="text-xs font-mono text-foreground truncate">{selectedNode.ipAddresses[1]}</code>
                    <button onclick={() => copyToClipboard(selectedNode.ipAddresses[1])} class="p-0.5 text-muted-foreground hover:text-foreground shrink-0"><Icon name="copy" size={12} /></button>
                  </div>
                </div>
              {/if}
            {/if}
          </div>

          <!-- Tags (Tailscale only) -->
          {#if selectedNode._type === 'tailscale'}
            <div class="mt-4 pt-4 border-t border-border">
              <div class="flex items-center justify-between mb-2">
                <h4 class="text-xs font-medium text-foreground uppercase tracking-wide">ACL Tags</h4>
                {#if !editingTags}
                  <button onclick={() => editingTags = true} class="p-1 text-muted-foreground hover:text-foreground hover:bg-accent rounded"><Icon name="edit" size={12} /></button>
                {/if}
              </div>
              {#if editingTags}
                <div class="flex items-center gap-2">
                  <Input bind:value={newTags} placeholder="server, trusted" class="kt-input-sm flex-1" />
                  <button onclick={saveTags} class="p-1.5 text-success hover:bg-success/10 rounded"><Icon name="check" size={16} /></button>
                  <button onclick={() => editingTags = false} class="p-1.5 text-muted-foreground hover:bg-accent rounded"><Icon name="x" size={16} /></button>
                </div>
              {:else}
                <div class="flex flex-wrap gap-1.5">
                  {#if selectedNode.forcedTags?.length > 0}
                    {#each selectedNode.forcedTags as tag}<Badge variant="muted" size="sm">{tag}</Badge>{/each}
                  {:else}
                    <span class="text-xs text-muted-foreground">No tags</span>
                  {/if}
                </div>
              {/if}
            </div>

            <!-- Routes -->
            {#if nodeRoutes.length > 0}
              <div class="mt-4 pt-4 border-t border-border">
                <h4 class="text-xs font-medium text-foreground uppercase tracking-wide mb-2">Routes</h4>
                <div class="flex flex-wrap gap-2">
                  {#each nodeRoutes as route}
                    <div class="inline-flex items-center gap-2 px-2 py-1 bg-muted/50 rounded text-xs">
                      <code class="font-mono">{route.prefix}</code>
                      <span class="w-1.5 h-1.5 rounded-full {route.enabled ? 'bg-success' : 'bg-muted-foreground'}"></span>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}
          {/if}

        {:else if activeTab === 'network'}
          <!-- Tailscale Network Tab -->
          <div class="space-y-3">
            <div class="p-3 bg-muted/50 rounded-lg">
              <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Node ID</div>
              <code class="text-sm font-mono text-foreground">{selectedNode.id}</code>
            </div>
            {#if selectedNode.registerMethod}
              <div class="p-3 bg-muted/50 rounded-lg">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Registration</div>
                <div class="text-sm text-foreground">{selectedNode.registerMethod.replace('REGISTER_METHOD_', '')}</div>
              </div>
            {/if}
            {#each [['Machine Key', selectedNode.machineKey], ['Node Key', selectedNode.nodeKey], ['Disco Key', selectedNode.discoKey]].filter(([,v]) => v) as [label, key]}
              <div class="p-3 bg-muted/50 rounded-lg">
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">{label}</div>
                <div class="flex items-center gap-1">
                  <code class="text-[10px] font-mono text-foreground break-all">{key}</code>
                  <button onclick={() => copyToClipboard(key)} class="p-0.5 text-muted-foreground hover:text-foreground shrink-0"><Icon name="copy" size={12} /></button>
                </div>
              </div>
            {/each}
          </div>

        {:else if activeTab === 'qr'}
          <!-- WireGuard QR & Config Tab - Side by side layout -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <!-- Left: Tunnel selector + actions -->
            <div class="space-y-4">
              <div>
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Tunnel Mode</div>
                <div class="grid grid-cols-2 gap-2">
                  <button
                    onclick={() => tunnelMode = 'full'}
                    class="p-3 border rounded-lg text-left transition-all {tunnelMode === 'full' ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/50'}"
                  >
                    <div class="text-sm font-medium text-foreground">Full</div>
                    <div class="text-[10px] text-muted-foreground">All traffic</div>
                  </button>
                  <button
                    onclick={() => tunnelMode = 'split'}
                    class="p-3 border rounded-lg text-left transition-all {tunnelMode === 'split' ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/50'}"
                  >
                    <div class="text-sm font-medium text-foreground">Split</div>
                    <div class="text-[10px] text-muted-foreground">VPN only</div>
                  </button>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-2">
                <Button onclick={downloadConfig} size="sm" icon="download" class="justify-center">
                  Download
                </Button>
                <Button onclick={copyConfig} variant="secondary" size="sm" icon="copy" class="justify-center">
                  Copy
                </Button>
              </div>

              <div class="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground">
                <p class="font-medium text-foreground mb-1">Quick Setup</p>
                <ol class="list-decimal list-inside space-y-0.5">
                  <li>Select tunnel mode</li>
                  <li>Scan QR or download config</li>
                  <li>Import to WireGuard app</li>
                </ol>
              </div>
            </div>

            <!-- Right: QR Code -->
            <div class="flex items-center justify-center p-4 bg-white rounded-xl min-h-[200px]">
              {#if qrLoading}
                <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              {:else if qrUrl}
                <img src={qrUrl} alt="QR Code" class="max-w-full max-h-[200px]" />
              {:else}
                <span class="text-muted-foreground text-sm">Failed to load</span>
              {/if}
            </div>
          </div>

        {:else if activeTab === 'access'}
          <!-- Access Control Tab -->
          <div class="space-y-4">
            {#if !selectedVpnClient}
              <!-- Not synced yet -->
              <div class="text-center py-6">
                <div class="w-12 h-12 rounded-full bg-muted/50 flex items-center justify-center mx-auto mb-3">
                  <Icon name="shield-lock" size={24} class="text-muted-foreground" />
                </div>
                <p class="text-sm text-muted-foreground mb-3">
                  This node hasn't been synced to the VPN access control system yet.
                </p>
                <Button onclick={syncVpnClients} size="sm" icon="refresh" disabled={aclSyncing}>
                  {aclSyncing ? 'Syncing...' : 'Sync VPN Clients'}
                </Button>
              </div>
            {:else}
              <!-- Access Policy -->
              <div>
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Access Policy</div>
                <div class="grid grid-cols-2 gap-2">
                  <button
                    onclick={() => aclPolicy = 'block_all'}
                    class="p-3 border rounded-lg text-left transition-all {aclPolicy === 'block_all' ? 'border-destructive bg-destructive/10' : 'border-border hover:border-destructive/50'}"
                  >
                    <div class="text-sm font-medium text-foreground">Block All</div>
                    <div class="text-[10px] text-muted-foreground">Isolated - no access</div>
                  </button>
                  <button
                    onclick={() => aclPolicy = 'selected'}
                    class="p-3 border rounded-lg text-left transition-all {aclPolicy === 'selected' ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/50'}"
                  >
                    <div class="text-sm font-medium text-foreground">Selected</div>
                    <div class="text-[10px] text-muted-foreground">Choose targets below</div>
                  </button>
                  <button
                    onclick={() => aclPolicy = 'allow_all'}
                    class="p-3 border rounded-lg text-left transition-all col-span-2 {aclPolicy === 'allow_all' ? 'border-warning bg-warning/10' : 'border-border hover:border-warning/50'}"
                  >
                    <div class="text-sm font-medium text-foreground">Allow All</div>
                    <div class="text-[10px] text-muted-foreground">Can reach all clients</div>
                  </button>
                </div>
              </div>

              {#if aclPolicy === 'selected'}
                <!-- Client Selection -->
                <div>
                  <div class="flex items-center justify-between mb-2">
                    <div class="text-[10px] uppercase tracking-wide text-muted-foreground">This client can reach:</div>
                    <span class="text-[10px] text-muted-foreground">{allowedClientIds.length} selected</span>
                  </div>
                  <div class="border border-border rounded-lg max-h-48 overflow-y-auto">
                    {#each vpnClients.filter(c => c.id !== selectedVpnClient?.id && c.aclPolicy !== 'block_all' && c.aclPolicy !== 'allow_all') as client}
                      <div class="flex items-center gap-2 p-2.5 border-b border-border last:border-b-0 hover:bg-accent/30 transition-colors">
                        <!-- Allow checkbox -->
                        <button
                          onclick={() => toggleAllowedClient(client.id)}
                          class="w-5 h-5 rounded border flex items-center justify-center shrink-0
                            {allowedClientIds.includes(client.id) ? 'bg-primary border-primary text-white' : 'border-border'}"
                        >
                          {#if allowedClientIds.includes(client.id)}
                            <Icon name="check" size={12} />
                          {/if}
                        </button>
                        <!-- Client info -->
                        <div class="flex-1 min-w-0" onclick={() => toggleAllowedClient(client.id)}>
                          <div class="text-sm font-medium text-foreground truncate cursor-pointer">{client.name}</div>
                          <div class="text-[10px] text-muted-foreground">{client.ip} • {client.type === 'wireguard' ? 'WG' : 'TS'}</div>
                        </div>
                        <!-- Bidirectional checkbox (only if allowed and target has 'selected' policy) -->
                        {#if allowedClientIds.includes(client.id) && client.aclPolicy === 'selected'}
                          <button
                            onclick={() => toggleBidirectional(client.id)}
                            class="flex items-center gap-1.5 px-2 py-1 rounded text-[10px] transition-colors shrink-0
                              {bidirectionalMap[client.id] ? 'bg-info/15 text-info border border-info/30' : 'bg-muted/50 text-muted-foreground border border-border hover:border-info/30'}"
                            title="Allow {client.name} to also reach this client"
                          >
                            <Icon name="arrows-right-left" size={12} />
                            Bi
                          </button>
                        {/if}
                      </div>
                    {:else}
                      <div class="p-4 text-center text-sm text-muted-foreground">
                        No eligible clients found
                      </div>
                    {/each}
                  </div>
                  <p class="text-[10px] text-muted-foreground mt-2">
                    <Icon name="info-circle" size={10} class="inline" /> Clients with "Block All" or "Allow All" policies are hidden. Use "Bi" to also allow them to reach you.
                  </p>
                </div>
              {/if}

              <!-- Save Button -->
              <div class="pt-2">
                <Button onclick={saveAcl} class="w-full justify-center" disabled={aclLoading}>
                  {aclLoading ? 'Saving...' : 'Save & Apply Rules'}
                </Button>
              </div>
            {/if}
          </div>

        {:else if activeTab === 'actions' || activeTab === 'security'}
          <!-- Actions Tab -->
          {#if confirmAction === 'delete'}
            <!-- Delete Confirmation -->
            <div class="space-y-4">
              <div class="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-destructive/15 text-destructive shrink-0">
                    <Icon name="alert-triangle" size={20} />
                  </div>
                  <div>
                    <p class="font-medium text-foreground">Delete {selectedNode._displayName}?</p>
                    <p class="text-sm text-muted-foreground mt-0.5">This action cannot be undone. The node will be permanently removed.</p>
                  </div>
                </div>
              </div>
              <div class="flex gap-2">
                <Button onclick={() => confirmAction = null} variant="secondary" class="flex-1 justify-center" disabled={actionLoading}>
                  Cancel
                </Button>
                <Button onclick={deleteNode} variant="destructive" class="flex-1 justify-center" disabled={actionLoading} icon={actionLoading ? undefined : "trash"}>
                  {#if actionLoading}
                    <span class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  {:else}
                    Delete
                  {/if}
                </Button>
              </div>
            </div>
          {:else if confirmAction === 'expire'}
            <!-- Expire Confirmation -->
            <div class="space-y-4">
              <div class="p-4 bg-warning/10 border border-warning/20 rounded-lg">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-warning/15 text-warning shrink-0">
                    <Icon name="alert-triangle" size={20} />
                  </div>
                  <div>
                    <p class="font-medium text-foreground">Expire key for {selectedNode._displayName}?</p>
                    <p class="text-sm text-muted-foreground mt-0.5">The device will need to re-authenticate to reconnect.</p>
                  </div>
                </div>
              </div>
              <div class="flex gap-2">
                <Button onclick={() => confirmAction = null} variant="secondary" class="flex-1 justify-center" disabled={actionLoading}>
                  Cancel
                </Button>
                <Button onclick={expireNode} class="flex-1 justify-center kt-btn-warning" disabled={actionLoading} icon={actionLoading ? undefined : "clock"}>
                  {#if actionLoading}
                    <span class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  {:else}
                    Expire Key
                  {/if}
                </Button>
              </div>
            </div>
          {:else}
            <!-- Normal Actions View -->
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {#if selectedNode._type === 'wireguard'}
                <button
                  onclick={toggleWgPeer}
                  class="flex items-center gap-3 p-4 border rounded-xl text-left hover:bg-accent/50 transition-colors
                    {selectedNode.enabled ? 'border-warning/30 hover:border-warning/50' : 'border-success/30 hover:border-success/50'}"
                >
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center shrink-0
                    {selectedNode.enabled ? 'bg-warning/15 text-warning' : 'bg-success/15 text-success'}">
                    <Icon name={selectedNode.enabled ? 'hand-off' : 'hand-stop'} size={20} />
                  </div>
                  <div>
                    <div class="font-medium text-foreground">{selectedNode.enabled ? 'Disable' : 'Enable'}</div>
                    <div class="text-xs text-muted-foreground">{selectedNode.enabled ? 'Block connections' : 'Allow connections'}</div>
                  </div>
                </button>
              {:else}
                <button
                  onclick={() => confirmAction = 'expire'}
                  class="flex items-center gap-3 p-4 border border-warning/30 rounded-xl text-left hover:bg-warning/5 hover:border-warning/50 transition-colors"
                >
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-warning/15 text-warning shrink-0">
                    <Icon name="clock" size={20} />
                  </div>
                  <div>
                    <div class="font-medium text-foreground">Expire Key</div>
                    <div class="text-xs text-muted-foreground">Force re-authentication</div>
                  </div>
                </button>
              {/if}

              <button
                onclick={() => confirmAction = 'delete'}
                class="flex items-center gap-3 p-4 border border-destructive/30 rounded-xl text-left hover:bg-destructive/5 hover:border-destructive/50 transition-colors"
              >
                <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-destructive/15 text-destructive shrink-0">
                  <Icon name="trash" size={20} />
                </div>
                <div>
                  <div class="font-medium text-foreground">Delete</div>
                  <div class="text-xs text-muted-foreground">Remove permanently</div>
                </div>
              </button>
            </div>
          {/if}
        {/if}
      </div>
  {/if}
</Modal>

<!-- Create WireGuard Peer Modal -->
<Modal bind:open={showCreateModal} title="Add WireGuard Node" size="md">
  {#if createdPeer}
    <div class="space-y-4">
      <div class="p-4 bg-success/10 border border-success/20 rounded-lg flex items-center gap-3">
        <div class="w-10 h-10 rounded-full bg-success/20 flex items-center justify-center shrink-0">
          <Icon name="check" size={20} class="text-success" />
        </div>
        <div>
          <p class="font-medium text-foreground">Peer created successfully!</p>
          <p class="text-xs text-muted-foreground mt-0.5">Save this configuration - the private key won't be shown again.</p>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-4">
        <div class="p-3 bg-muted/50 rounded-lg">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Name</div>
          <div class="flex items-center gap-2">
            <Icon name="device-desktop" size={14} class="text-muted-foreground" />
            <span class="text-sm font-medium text-foreground">{createdPeer.name}</span>
          </div>
        </div>
        <div class="p-3 bg-muted/50 rounded-lg">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">IP Address</div>
          <div class="flex items-center gap-2">
            <Icon name="network" size={14} class="text-muted-foreground" />
            <code class="text-sm font-mono text-foreground">{createdPeer.ipAddress}</code>
          </div>
        </div>
      </div>
    </div>
  {:else}
    <Input
      label="Device Name"
      helperText="A friendly name to identify this device"
      bind:value={newPeerName}
      placeholder="e.g., iPhone, Laptop, Home Router"
    />
  {/if}

  {#snippet footer()}
    {#if createdPeer}
      <Button
        onclick={async () => {
          const config = await apiGetText(`/api/wg/peers/${createdPeer.id}/config`)
          const blob = new Blob([config], { type: 'text/plain' })
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = `${createdPeer.name}.conf`
          a.click()
          URL.revokeObjectURL(url)
          toast('Config downloaded', 'success')
        }}
        icon="download"
      >
        Download
      </Button>
      <Button
        onclick={async () => {
          const config = await apiGetText(`/api/wg/peers/${createdPeer.id}/config`)
          copyToClipboard(config)
        }}
        variant="secondary"
        icon="copy"
      >
        Copy Config
      </Button>
      <Button onclick={() => showCreateModal = false} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
      <Button onclick={createWgPeer}>Create WireGuard Device</Button>
    {/if}
  {/snippet}
</Modal>
