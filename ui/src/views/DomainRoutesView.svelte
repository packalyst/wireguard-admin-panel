<script>
  import { toast, apiGet, apiPost, apiPut, apiDelete, confirm, setConfirmLoading } from '../stores/app.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import { filterByFields } from '$lib/utils/data.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Checkbox from '../components/Checkbox.svelte'

  let { loading = $bindable(true) } = $props()

  // Multi-source data loading
  const loader = useDataLoader([
    { fn: () => apiGet('/api/domains'), key: 'routes', extract: 'routes', isArray: true },
    { fn: () => apiGet('/api/vpn/clients'), key: 'clients', isArray: true },
    { fn: () => apiGet('/api/traefik/overview'), key: 'traefik', default: {} },
    { fn: () => apiGet('/api/domains/certificates').catch(() => ({ certificates: [] })), key: 'certs', default: { certificates: [] } }
  ])

  const routes = $derived(loader.data.routes || [])
  const vpnClients = $derived(loader.data.clients || [])
  const certificates = $derived(loader.data.certs?.certificates || [])
  const availableMiddlewares = $derived.by(() => {
    const mws = loader.data.traefik?.middlewares || []
    return mws
      .filter(m => m.provider === 'file' && !m.name.includes('@internal'))
      .map(m => ({ name: m.name, type: m.type }))
  })

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  let searchQuery = $state('')

  // Modal states
  let formModalMode = $state(null) // 'create' | 'edit' | null
  let showFormModal = $derived(formModalMode !== null)
  let showScanModal = $state(false)
  let editingRoute = $state(null)

  // Port scanning state
  let scanMode = $state('common') // common, range, full
  let scanning = $state(false)
  let scanProgress = $state({ total: 0, scanned: 0, found: 0, completed: false })
  let discoveredPorts = $state([])
  let selectedPorts = $state([]) // Array of {port, domain, description, middlewares, httpsBackend}
  let scanClientId = $state(null)
  let scanClientIp = $state('')
  let scanClientName = $state('')
  let scanAbortController = null

  // Form state
  let formData = $state({
    domain: '',
    targetIp: '',
    targetPort: 80,
    vpnClientId: null,
    httpsBackend: false,
    middlewares: [],
    description: '',
    accessMode: 'vpn',
    frontendSsl: false
  })

  // Certificate lookup by domain
  function getCertForDomain(domain) {
    return certificates.find(c => c.domain === domain)
  }

  // Filtered routes
  const filteredRoutes = $derived(
    filterByFields(routes, ['domain', 'targetIp', 'description', 'vpnClientName'], searchQuery)
  )

  // VPN client options for select
  const clientOptions = $derived([
    { value: '', label: 'Manual IP' },
    ...vpnClients.map(c => ({ value: c.id, label: `${c.name} (${c.ip})` }))
  ])

  function resetForm() {
    formData = {
      domain: '',
      targetIp: '',
      targetPort: 80,
      vpnClientId: null,
      httpsBackend: false,
      middlewares: [],
      description: '',
      accessMode: 'vpn',
      frontendSsl: false
    }
  }

  function openCreateModal() {
    resetForm()
    editingRoute = null
    formModalMode = 'create'
  }

  function openEditModal(route) {
    editingRoute = route
    formData = {
      domain: route.domain,
      targetIp: route.targetIp,
      targetPort: route.targetPort,
      vpnClientId: route.vpnClientId || '',
      httpsBackend: route.httpsBackend,
      middlewares: route.middlewares || [],
      description: route.description || '',
      accessMode: route.accessMode || 'vpn',
      frontendSsl: route.frontendSsl || false
    }
    formModalMode = 'edit'
  }

  function closeFormModal() {
    formModalMode = null
    editingRoute = null
  }

  function toggleMiddleware(mwName) {
    if (formData.middlewares.includes(mwName)) {
      formData.middlewares = formData.middlewares.filter(m => m !== mwName)
    } else {
      formData.middlewares = [...formData.middlewares, mwName]
    }
  }

  async function confirmDelete(route) {
    const confirmed = await confirm({
      title: 'Delete Domain Route',
      message: `Delete route for ${route.domain}?`,
      description: 'This action cannot be undone.'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiDelete(`/api/domains/${route.id}`)
      toast('Domain route deleted', 'success')
      loader.reload()
    } catch (e) {
      toast('Failed to delete route: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  // When VPN client is selected, auto-fill the IP
  function onClientChange(e) {
    const clientId = e.target.value
    formData.vpnClientId = clientId || null
    if (clientId) {
      const client = vpnClients.find(c => c.id == clientId)
      if (client) {
        formData.targetIp = client.ip
      }
    }
  }

  async function createRoute() {
    if (!formData.domain || !formData.targetIp || !formData.targetPort) {
      toast('Domain, IP, and Port are required', 'error')
      return
    }
    try {
      await apiPost('/api/domains', {
        domain: formData.domain,
        targetIp: formData.targetIp,
        targetPort: parseInt(formData.targetPort),
        vpnClientId: formData.vpnClientId ? parseInt(formData.vpnClientId) : null,
        httpsBackend: formData.httpsBackend,
        middlewares: formData.middlewares,
        description: formData.description,
        accessMode: formData.accessMode,
        frontendSsl: formData.frontendSsl
      })
      toast('Domain route created', 'success')
      closeFormModal()
      loader.reload()
    } catch (e) {
      toast('Failed to create route: ' + e.message, 'error')
    }
  }

  async function updateRoute() {
    if (!editingRoute) return
    try {
      await apiPut(`/api/domains/${editingRoute.id}`, {
        domain: formData.domain,
        targetIp: formData.targetIp,
        targetPort: parseInt(formData.targetPort),
        vpnClientId: formData.vpnClientId ? parseInt(formData.vpnClientId) : null,
        httpsBackend: formData.httpsBackend,
        middlewares: formData.middlewares,
        description: formData.description,
        accessMode: formData.accessMode,
        frontendSsl: formData.frontendSsl
      })
      toast('Domain route updated', 'success')
      closeFormModal()
      loader.reload()
    } catch (e) {
      toast('Failed to update route: ' + e.message, 'error')
    }
  }

  function submitForm() {
    if (formModalMode === 'create') {
      createRoute()
    } else if (formModalMode === 'edit') {
      updateRoute()
    }
  }

  async function toggleRoute(route) {
    try {
      await apiPost(`/api/domains/${route.id}/toggle`)
      toast(`Route ${route.enabled ? 'disabled' : 'enabled'}`, 'success')
      loader.reload()
    } catch (e) {
      toast('Failed to toggle route: ' + e.message, 'error')
    }
  }

  // Port scanning functions
  function openScanModal() {
    scanMode = 'common'
    scanning = false
    scanProgress = { total: 0, scanned: 0, found: 0, completed: false }
    discoveredPorts = []
    selectedPorts = []
    scanClientId = null
    scanClientIp = ''
    showScanModal = true
  }

  function onScanClientChange(e) {
    const clientId = e.target.value
    scanClientId = clientId || null
    if (clientId) {
      const client = vpnClients.find(c => c.id == clientId)
      if (client) {
        scanClientIp = client.ip
        scanClientName = client.name
      }
    } else {
      scanClientIp = ''
      scanClientName = ''
    }
    // Reset ports when client changes
    discoveredPorts = []
    selectedPorts = []
  }

  async function startScan() {
    if (!scanClientId) {
      toast('Please select a VPN client to scan', 'error')
      return
    }

    scanning = true
    scanProgress = { total: 0, scanned: 0, found: 0, completed: false }
    discoveredPorts = []
    selectedPorts = []

    try {
      const res = await apiPost(`/api/vpn/clients/${scanClientId}/scan`, { mode: scanMode })
      discoveredPorts = res.ports || []
      scanProgress = { total: res.count, scanned: res.count, found: res.count, completed: true }
      if (res.count === 0) {
        toast('No open ports found', 'info')
      } else {
        toast(`Found ${res.count} open ports`, 'success')
      }
    } catch (e) {
      toast('Scan failed: ' + e.message, 'error')
    } finally {
      scanning = false
    }
  }

  function cancelScan() {
    if (scanAbortController) {
      scanAbortController.abort()
    }
    scanning = false
  }

  function togglePortSelection(port) {
    const existing = selectedPorts.find(p => p.port === port)
    if (existing) {
      selectedPorts = selectedPorts.filter(p => p.port !== port)
    } else {
      // Create editable entry with defaults
      const portInfo = discoveredPorts.find(p => p.port === port)
      const serviceName = portInfo?.service || `port-${port}`
      const clientName = scanClientName?.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'device'
      selectedPorts = [...selectedPorts, {
        port,
        service: serviceName,
        domain: `${clientName}-${serviceName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.local`,
        description: `${serviceName} on ${scanClientName || 'device'}`,
        middlewares: [],
        httpsBackend: false
      }]
    }
  }

  function selectAllPorts() {
    const clientName = scanClientName?.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'device'
    selectedPorts = discoveredPorts.map(p => {
      const serviceName = p.service || `port-${p.port}`
      return {
        port: p.port,
        service: serviceName,
        domain: `${clientName}-${serviceName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.local`,
        description: `${serviceName} on ${scanClientName || 'device'}`,
        middlewares: [],
        httpsBackend: false
      }
    })
  }

  function deselectAllPorts() {
    selectedPorts = []
  }

  function updateSelectedPort(port, field, value) {
    selectedPorts = selectedPorts.map(p =>
      p.port === port ? { ...p, [field]: value } : p
    )
  }

  function toggleSelectedPortMiddleware(port, mwName) {
    selectedPorts = selectedPorts.map(p => {
      if (p.port !== port) return p
      const mws = p.middlewares || []
      if (mws.includes(mwName)) {
        return { ...p, middlewares: mws.filter(m => m !== mwName) }
      } else {
        return { ...p, middlewares: [...mws, mwName] }
      }
    })
  }

  async function createRoutesFromScan() {
    if (selectedPorts.length === 0) {
      toast('Please select at least one port', 'error')
      return
    }

    let created = 0
    let errors = []

    for (const entry of selectedPorts) {
      try {
        await apiPost('/api/domains', {
          domain: entry.domain,
          targetIp: scanClientIp,
          targetPort: entry.port,
          vpnClientId: parseInt(scanClientId),
          httpsBackend: entry.httpsBackend,
          middlewares: entry.middlewares || [],
          description: entry.description
        })
        created++
      } catch (e) {
        errors.push(`${entry.domain}: ${e.message}`)
      }
    }

    if (created > 0) {
      toast(`Created ${created} route(s)`, 'success')
      showScanModal = false
      loader.reload()
    }
    if (errors.length > 0) {
      toast(`${errors.length} failed: ${errors[0]}`, 'warning')
    }
  }

  // Port options for manual selection (from discovered ports + common)
  const portOptions = $derived([
    { value: '', label: 'Select port...' },
    ...discoveredPorts.map(p => ({ value: p.port, label: `${p.port} - ${p.service || 'Unknown'}` }))
  ])

  // Use discovered port when selected
  function onPortSelect(e) {
    const port = e.target.value
    if (port) {
      formData.targetPort = parseInt(port)
    }
  }
</script>

<div class="space-y-4">
  <InfoCard
    icon="world-www"
    title="Domain Routes"
    description="Map custom domains to services running on your VPN devices. Routes are handled by Traefik reverse proxy with automatic DNS configuration via AdGuard."
  />

  <!-- Toolbar -->
  <Toolbar bind:search={searchQuery} placeholder="Search domains...">
    <div class="kt-btn-group">
      <Button variant="outline" size="sm" icon="scan" onclick={openScanModal}>
        Scan
      </Button>
      <Button size="sm" icon="plus" onclick={openCreateModal}>
        Add Route
      </Button>
    </div>
  </Toolbar>

  <!-- Routes List -->
  {#if routes.length > 0}
    {#if filteredRoutes.length > 0}
      <div class="space-y-2">
        {#each filteredRoutes as route}
          <div class="bg-card border border-border rounded-lg px-4 py-3 hover:border-primary/30 transition-colors">
            <div class="flex flex-wrap sm:flex-nowrap items-center gap-3 sm:gap-4">
              <!-- Domain + Description -->
              <div class="flex items-center gap-3 min-w-0 flex-1 sm:flex-none sm:min-w-[240px]">
                <div class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 {route.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                  <Icon name="world-www" size={16} />
                </div>
                <div class="min-w-0">
                  <code class="font-medium text-sm text-foreground">{route.domain}</code>
                  {#if route.description}
                    <p class="text-[11px] text-muted-foreground truncate">{route.description}</p>
                  {/if}
                </div>
              </div>

              <!-- Mobile: Status + Actions aligned right -->
              <div class="flex flex-col items-end gap-1.5 sm:hidden">
                <div class="flex items-center gap-1">
                  <Badge variant={route.enabled ? 'success' : 'muted'} size="sm">
                    {route.enabled ? 'Enabled' : 'Disabled'}
                  </Badge>
                  {#if getCertForDomain(route.domain)}
                    {@const cert = getCertForDomain(route.domain)}
                    <Badge variant={cert.status === 'valid' ? 'success' : cert.status === 'warning' ? 'warning' : 'destructive'} size="sm">
                      SSL
                    </Badge>
                  {:else if route.frontendSsl}
                    <Badge variant="muted" size="sm">SSL?</Badge>
                  {/if}
                </div>
                <div class="btn-group">
                  <button onclick={() => toggleRoute(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name={route.enabled ? 'player-pause' : 'player-play'} size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">{route.enabled ? 'Disable' : 'Enable'}</span>
                  </button>
                  <button onclick={() => openEditModal(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name="pencil" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Edit</span>
                  </button>
                  <button onclick={() => confirmDelete(route)} class="custom_btns text-destructive" data-kt-tooltip>
                    <Icon name="trash" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Delete</span>
                  </button>
                </div>
              </div>

              <!-- Desktop: Inline layout -->
              <div class="hidden sm:contents">
                <!-- Status -->
                <Badge variant={route.enabled ? 'success' : 'muted'} size="sm">
                  {route.enabled ? 'Enabled' : 'Disabled'}
                </Badge>

                <!-- Target -->
                <code class="text-xs text-muted-foreground font-mono">
                  {route.targetIp}:{route.targetPort}
                </code>

                <!-- Device -->
                <span class="text-xs text-muted-foreground hidden md:inline">
                  {route.vpnClientName || '—'}
                </span>

                <!-- Options -->
                <div class="hidden md:flex items-center gap-1">
                  <!-- Access Mode Badge -->
                  <Badge variant={route.accessMode === 'public' ? 'warning' : 'info'} size="sm">
                    {route.accessMode === 'public' ? 'Public' : 'VPN'}
                  </Badge>
                  <!-- Frontend SSL Badge with certificate status -->
                  {#if getCertForDomain(route.domain)}
                    {@const cert = getCertForDomain(route.domain)}
                    <Badge
                      variant={cert.status === 'valid' ? 'success' : cert.status === 'warning' ? 'warning' : 'destructive'}
                      size="sm"
                      title={`Expires: ${new Date(cert.notAfter).toLocaleDateString()} (${cert.daysLeft} days)`}
                    >
                      SSL {cert.daysLeft}d
                    </Badge>
                  {:else if route.frontendSsl}
                    <Badge variant="muted" size="sm" title="SSL enabled, waiting for certificate">
                      SSL Pending
                    </Badge>
                  {/if}
                  <!-- Backend HTTPS Badge -->
                  {#if route.httpsBackend}
                    <Badge variant="muted" size="sm">HTTPS↗</Badge>
                  {/if}
                  {#each (route.middlewares || []).filter(m => !m.includes('vpn-only')).slice(0, 2) as mw}
                    <Badge variant="muted" size="sm">{mw.replace('@file', '')}</Badge>
                  {/each}
                  {#if (route.middlewares || []).filter(m => !m.includes('vpn-only')).length > 2}
                    <span class="text-[10px] text-muted-foreground">+{route.middlewares.filter(m => !m.includes('vpn-only')).length - 2}</span>
                  {/if}
                </div>

                <!-- Spacer -->
                <div class="flex-1"></div>

                <!-- Actions -->
                <div class="btn-group">
                  <button onclick={() => toggleRoute(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name={route.enabled ? 'player-pause' : 'player-play'} size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">{route.enabled ? 'Disable' : 'Enable'}</span>
                  </button>
                  <button onclick={() => openEditModal(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name="pencil" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Edit</span>
                  </button>
                  <button onclick={() => confirmDelete(route)} class="custom_btns text-destructive" data-kt-tooltip>
                    <Icon name="trash" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Delete</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {:else}
      <EmptyState
        icon="search"
        title="No matching routes"
        description="Try adjusting your search query"
      />
    {/if}
  {:else}
    <EmptyState
      icon="world-www"
      title="No domain routes"
      description="Create your first domain route to map a custom domain to a service on your VPN"
    />
  {/if}
</div>

<!-- Create/Edit Modal -->
<Modal open={showFormModal} onclose={closeFormModal} title={formModalMode === 'create' ? 'Add Domain Route' : 'Edit Domain Route'} size="md">
  <div class="space-y-4">
    <Input
      label="Domain"
      placeholder="wiki.local"
      bind:value={formData.domain}
      prefixIcon="world-www"
      suffixCheckbox={{ icon: "lock", label: "SSL", color: "warning" }}
      bind:suffixCheckboxChecked={formData.frontendSsl}
    />

    <Select
      label="VPN Device (optional)"
      value={formData.vpnClientId || ''}
      onchange={onClientChange}
    >
      {#each clientOptions as opt}
        <option value={opt.value}>{opt.label}</option>
      {/each}
    </Select>

    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Target IP"
        placeholder="10.8.0.5"
        bind:value={formData.targetIp}
        prefixIcon="network"
        suffixCheckbox={{ icon: "lock", label: "HTTPS", color: "warning" }}
        bind:suffixCheckboxChecked={formData.httpsBackend}
      />
      <Input
        label="Target Port"
        type="number"
        placeholder="8000"
        bind:value={formData.targetPort}
        prefixIcon="plug"
      />
    </div>

    <Input
      label="Description (optional)"
      placeholder="Wiki.js on Raspberry Pi"
      bind:value={formData.description}
      prefixIcon="file-text"
    />

    <!-- Access Mode -->
    <div>
      <label class="text-sm font-medium text-foreground">Access Mode</label>
      <div class="mt-2 flex gap-2">
        <Checkbox
          variant="chip"
          checked={formData.accessMode === 'vpn'}
          onchange={() => formData.accessMode = 'vpn'}
          icon="lock"
          label="VPN Only"
        />
        <Checkbox
          variant="chip"
          color="warning"
          checked={formData.accessMode === 'public'}
          onchange={() => formData.accessMode = 'public'}
          icon="world"
          label="Public"
        />
      </div>
    </div>

    {#if availableMiddlewares.length > 0}
      <div>
        <label class="text-sm font-medium text-foreground">Middlewares</label>
        <div class="mt-2 flex flex-wrap gap-2">
          {#each availableMiddlewares as mw}
            <Checkbox
              variant="chip"
              checked={formData.middlewares.includes(mw.name)}
              onchange={() => toggleMiddleware(mw.name)}
              label={mw.name.replace('@file', '')}
            />
          {/each}
        </div>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <div class="flex justify-between w-full">
      <Button variant="outline" onclick={closeFormModal}>Cancel</Button>
      <Button variant="primary" onclick={submitForm}>
        {formModalMode === 'create' ? 'Create Route' : 'Save Changes'}
      </Button>
    </div>
  {/snippet}
</Modal>

<!-- Port Scan Modal -->
<Modal bind:open={showScanModal} title="Scan VPN Client Ports" size="lg">
  <div class="space-y-4">
    <!-- Client Selection -->
    <div class="grid grid-cols-2 gap-4">
      <Select
        label="VPN Device"
        value={scanClientId || ''}
        onchange={onScanClientChange}
      >
        <option value="">Select a device...</option>
        {#each vpnClients as client}
          <option value={client.id}>{client.name} ({client.ip})</option>
        {/each}
      </Select>

      <Select
        label="Scan Mode"
        bind:value={scanMode}
        disabled={scanning}
      >
        <option value="common">Common Ports (~140)</option>
        <option value="range">Port Range (from settings)</option>
        <option value="full">Full Scan (1-65535)</option>
      </Select>
    </div>

    {#if scanClientIp}
      <p class="text-xs text-muted-foreground">
        Target IP: <code class="font-mono">{scanClientIp}</code>
      </p>
    {/if}

    <!-- Scan Controls -->
    <div class="flex items-center gap-2">
      <Button
        variant="primary"
        size="sm"
        icon="scan"
        onclick={startScan}
        loading={scanning}
        disabled={!scanClientId}
      >
        {scanning ? 'Scanning...' : 'Start Scan'}
      </Button>
      {#if scanning}
        <Button variant="outline" size="sm" icon="x" onclick={cancelScan}>
          Cancel
        </Button>
      {/if}
    </div>

    <!-- Progress Bar -->
    {#if scanning}
      <div class="space-y-1">
        <div class="w-full h-2 bg-muted rounded-full overflow-hidden">
          <div
            class="h-full bg-primary transition-all duration-300"
            style="width: 100%"
          ></div>
        </div>
        <p class="text-xs text-muted-foreground">
          Scanning ports... This may take a moment.
        </p>
      </div>
    {/if}

    <!-- Discovered Ports -->
    {#if discoveredPorts.length > 0}
      <div class="kt-panel">
        <div class="kt-panel-header !py-2">
          <span class="text-xs font-medium text-foreground">
            Found {discoveredPorts.length} open port(s) — {selectedPorts.length} selected
          </span>
          <div class="flex items-center gap-2">
            <button onclick={selectAllPorts} class="text-xs text-primary hover:underline">
              Select All
            </button>
            <span class="text-muted-foreground">|</span>
            <button onclick={deselectAllPorts} class="text-xs text-primary hover:underline">
              Deselect All
            </button>
          </div>
        </div>
        <div class="max-h-[400px] overflow-y-auto divide-y divide-border">
          {#each discoveredPorts as portInfo}
            {@const entry = selectedPorts.find(p => p.port === portInfo.port)}
            {@const isSelected = !!entry}
            <div class="hover:bg-accent/30">
              <!-- Port header row -->
              <Checkbox
                checked={isSelected}
                onchange={() => togglePortSelection(portInfo.port)}
                class="!flex !gap-3 px-3 py-2"
              >
                <div class="flex-1 flex items-center gap-2">
                  <span class="font-mono text-sm font-medium text-foreground">{portInfo.port}</span>
                  {#if portInfo.service}
                    <span class="text-sm text-muted-foreground">{portInfo.service}</span>
                  {/if}
                </div>
                {#if isSelected}
                  <Icon name="chevron-down" size={14} class="text-muted-foreground" />
                {/if}
              </Checkbox>

              <!-- Inline editor when selected -->
              {#if isSelected && entry}
                <div class="px-3 pb-3 pt-1 ml-6 border-l-2 border-primary/30 space-y-3">
                  <Input
                    label="Domain"
                    placeholder="wiki.local"
                    value={entry.domain}
                    oninput={(e) => updateSelectedPort(entry.port, 'domain', e.target.value)}
                    prefixIcon="world-www"
                    suffixCheckbox={{ icon: "lock", label: "HTTPS", color: "warning" }}
                    suffixCheckboxChecked={entry.httpsBackend}
                    onSuffixCheckboxChange={(e) => updateSelectedPort(entry.port, 'httpsBackend', e.target.checked)}
                  />

                  <Input
                    label="Description"
                    placeholder="Service description"
                    value={entry.description}
                    oninput={(e) => updateSelectedPort(entry.port, 'description', e.target.value)}
                    prefixIcon="file-text"
                  />

                  {#if availableMiddlewares.length > 0}
                    <div class="flex items-center gap-2 flex-wrap">
                      <span class="text-xs text-muted-foreground">Middlewares:</span>
                      {#each availableMiddlewares as mw}
                        <Checkbox
                          variant="chip"
                          checked={(entry.middlewares || []).includes(mw.name)}
                          onchange={() => toggleSelectedPortMiddleware(entry.port, mw.name)}
                          label={mw.name.replace('@file', '')}
                        />
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {:else if scanProgress.completed && discoveredPorts.length === 0}
      <div class="text-center py-6 text-muted-foreground">
        <Icon name="search" size={32} class="mx-auto mb-2 opacity-50" />
        <p class="text-sm">No open ports found on this device</p>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <div class="flex justify-between w-full">
      <Button variant="outline" onclick={() => showScanModal = false}>Cancel</Button>
      <Button
        variant="primary"
        onclick={createRoutesFromScan}
        disabled={selectedPorts.length === 0}
      >
        Create {selectedPorts.length} Route(s)
      </Button>
    </div>
  {/snippet}
</Modal>
