<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete } from '../stores/app.js'
  import { formatNumber } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import StatCard from '../components/StatCard.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import blocklists from '../data/blocklists.json'

  let { loading = $bindable(true) } = $props()

  // Core state
  let activeTab = $state('overview')
  let status = $state(null)
  let stats = $state(null)

  // Tab-specific state (loaded on demand)
  let filters = $state([])
  let blockedServices = $state([])
  let allServices = $state([])
  let userRules = $state([])
  let safeBrowsing = $state(null)
  let parental = $state(null)
  let safeSearch = $state(null)
  let rewrites = $state([])

  // Track which tabs have been loaded
  let loadedTabs = $state({})

  // Modals
  let showAddFilterModal = $state(false)
  let addFilterMode = $state('list') // 'list' or 'manual'
  let selectedLists = $state([])
  let filterSearchQuery = $state('')
  let newFilterName = $state('')
  let newFilterUrl = $state('')
  let newRewriteDomain = $state('')
  let newRewriteAnswer = $state('')

  // Forms
  let newBlockDomain = $state('')
  let newAllowDomain = $state('')

  // Tab definitions
  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'layout' },
    { id: 'filters', label: 'Filters', icon: 'filter' },
    { id: 'rules', label: 'Block Rules', icon: 'ban' },
    { id: 'rewrites', label: 'DNS Rewrites', icon: 'link' }
  ]

  // Service categories (fallback if API doesn't provide)
  const SERVICE_CATEGORIES = [
    { id: 'social', name: 'Social Media', services: ['facebook', 'instagram', 'tiktok', 'twitter', 'snapchat', 'pinterest', 'reddit', 'linkedin'] },
    { id: 'video', name: 'Video Streaming', services: ['youtube', 'twitch', 'netflix', 'amazon_prime_video', 'disney_plus', 'hulu'] },
    { id: 'messaging', name: 'Messaging', services: ['whatsapp', 'telegram', 'discord', 'viber', 'signal', 'skype'] },
    { id: 'gaming', name: 'Gaming', services: ['steam', 'epicgames', 'origin', 'riot_games', 'blizzard'] },
    { id: 'other', name: 'Other', services: ['spotify', 'tinder', 'ebay'] },
  ]

  // Load core data (status/stats) on mount
  async function loadCoreData() {
    try {
      const [statusRes, statsRes, sbRes, parentalRes, ssRes, blockedRes, allRes] = await Promise.all([
        apiGet('/api/adguard/status').catch(() => null),
        apiGet('/api/adguard/stats').catch(() => null),
        apiGet('/api/adguard/safebrowsing').catch(() => null),
        apiGet('/api/adguard/parental').catch(() => null),
        apiGet('/api/adguard/safesearch').catch(() => null),
        apiGet('/api/adguard/blocked').catch(() => null),
        apiGet('/api/adguard/blocked/all').catch(() => null)
      ])
      status = statusRes
      stats = statsRes
      safeBrowsing = sbRes
      parental = parentalRes
      safeSearch = ssRes
      blockedServices = Array.isArray(blockedRes) ? blockedRes : (blockedRes?.ids || [])
      if (allRes?.blocked_services) {
        allServices = allRes.blocked_services
      }
      loadedTabs.services = true
      loadedTabs.safety = true
    } catch (e) {
      toast('Failed to load AdGuard data: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // Tab-specific loaders
  async function loadFilters() {
    if (loadedTabs.filters) return
    try {
      const res = await apiGet('/api/adguard/filtering')
      filters = res?.filters || []
      userRules = res?.user_rules || []
      loadedTabs.filters = true
      loadedTabs.rules = true
    } catch (e) {
      toast('Failed to load filters: ' + e.message, 'error')
    }
  }

  async function loadServices() {
    if (loadedTabs.services) return
    try {
      const [blockedRes, allRes] = await Promise.all([
        apiGet('/api/adguard/blocked'),
        apiGet('/api/adguard/blocked/all').catch(() => null)
      ])
      blockedServices = Array.isArray(blockedRes) ? blockedRes : (blockedRes?.ids || [])
      if (allRes?.blocked_services) {
        allServices = allRes.blocked_services
      }
      loadedTabs.services = true
    } catch (e) {
      toast('Failed to load services: ' + e.message, 'error')
    }
  }

  async function loadSafety() {
    if (loadedTabs.safety) return
    try {
      const [sbRes, parentalRes, ssRes] = await Promise.all([
        apiGet('/api/adguard/safebrowsing'),
        apiGet('/api/adguard/parental'),
        apiGet('/api/adguard/safesearch')
      ])
      safeBrowsing = sbRes
      parental = parentalRes
      safeSearch = ssRes
      loadedTabs.safety = true
    } catch (e) {
      toast('Failed to load safety settings: ' + e.message, 'error')
    }
  }

  async function loadRewrites() {
    if (loadedTabs.rewrites) return
    try {
      rewrites = await apiGet('/api/adguard/rewrites')
      loadedTabs.rewrites = true
    } catch (e) {
      toast('Failed to load rewrites: ' + e.message, 'error')
    }
  }

  // Load tab data when tab changes
  $effect(() => {
    if (activeTab === 'filters') loadFilters()
    else if (activeTab === 'rules') loadFilters()
    else if (activeTab === 'rewrites') loadRewrites()
  })

  // Computed
  const blockedDomains = $derived(
    userRules
      .filter(r => r.startsWith('||') && !r.startsWith('@@'))
      .map(r => r.replace('||', '').replace('^', ''))
  )

  const allowedDomains = $derived(
    userRules
      .filter(r => r.startsWith('@@||'))
      .map(r => r.replace('@@||', '').replace('^', ''))
  )

  const blockedQueries = $derived(stats?.num_blocked_filtering || 0)
  const totalQueries = $derived(stats?.num_dns_queries || 0)
  const blockPercent = $derived(totalQueries > 0 ? ((blockedQueries / totalQueries) * 100).toFixed(1) : 0)
  const enabledFilters = $derived(filters.filter(f => f.enabled).length)

  // Helper to get services by category
  function getServicesByCategory(categoryId) {
    const category = SERVICE_CATEGORIES.find(c => c.id === categoryId)
    if (!category) return []

    // If we have all services from API, filter by category
    if (allServices.length > 0) {
      return allServices.filter(s => category.services.includes(s.id))
    }

    // Fallback to hardcoded
    return category.services.map(id => ({ id, name: id.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) }))
  }

  // Actions
  async function toggleProtection(enabled) {
    try {
      await apiPost('/api/adguard/protection', { enabled })
      toast(enabled ? 'Protection enabled' : 'Protection disabled', 'success')
      status = { ...status, protection_enabled: enabled }
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function addFilter() {
    if (addFilterMode === 'manual') {
      if (!newFilterName || !newFilterUrl) return
      try {
        await apiPost('/api/adguard/filtering/add', { name: newFilterName, url: newFilterUrl })
        toast('Filter added', 'success')
        newFilterName = ''
        newFilterUrl = ''
        showAddFilterModal = false
        loadedTabs.filters = false
        loadFilters()
      } catch (e) {
        toast('Failed: ' + e.message, 'error')
      }
    } else {
      // Add selected lists
      if (selectedLists.length === 0) return
      let added = 0
      let failed = 0
      for (const listId of selectedLists) {
        const list = blocklists.categories.flatMap(c => c.lists).find(l => l.id === listId)
        if (list) {
          try {
            await apiPost('/api/adguard/filtering/add', { name: list.name, url: list.url })
            added++
          } catch (e) {
            failed++
          }
        }
      }
      if (added > 0) toast(`Added ${added} filter${added > 1 ? 's' : ''}`, 'success')
      if (failed > 0) toast(`Failed to add ${failed} filter${failed > 1 ? 's' : ''}`, 'error')
      selectedLists = []
      filterSearchQuery = ''
      showAddFilterModal = false
      loadedTabs.filters = false
      loadFilters()
    }
  }

  function toggleListSelection(listId) {
    if (selectedLists.includes(listId)) {
      selectedLists = selectedLists.filter(id => id !== listId)
    } else {
      selectedLists = [...selectedLists, listId]
    }
  }

  function isListAlreadyAdded(url) {
    return filters.some(f => f.url === url)
  }

  const filteredBlocklists = $derived(
    blocklists.categories.map(category => ({
      ...category,
      lists: category.lists.filter(list => {
        if (filterSearchQuery) {
          return list.name.toLowerCase().includes(filterSearchQuery.toLowerCase())
        }
        return true
      })
    })).filter(category => category.lists.length > 0)
  )

  async function removeFilter(url) {
    try {
      await apiPost('/api/adguard/filtering/remove', { url })
      toast('Filter removed', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleFilter(url, name, enabled) {
    try {
      await apiPost('/api/adguard/filtering/toggle', { url, name, enabled })
      // Update local state optimistically
      filters = filters.map(f => f.url === url ? { ...f, enabled } : f)
      toast(enabled ? 'Filter enabled' : 'Filter disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function refreshFilters() {
    try {
      await apiPost('/api/adguard/filtering/refresh')
      toast('Filters updated', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function addRule(rule) {
    try {
      const newRules = [...userRules, rule]
      await apiPost('/api/adguard/filtering/rules', { rules: newRules })
      toast('Rule added', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function removeRule(rule) {
    try {
      const newRules = userRules.filter(r => r !== rule)
      await apiPost('/api/adguard/filtering/rules', { rules: newRules })
      toast('Rule removed', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function handleAddBlockRule() {
    if (newBlockDomain) {
      addRule(`||${newBlockDomain}^`)
      newBlockDomain = ''
    }
  }

  function handleAddAllowRule() {
    if (newAllowDomain) {
      addRule(`@@||${newAllowDomain}^`)
      newAllowDomain = ''
    }
  }

  async function toggleService(serviceId, blocked) {
    try {
      const newServices = blocked
        ? [...blockedServices, serviceId]
        : blockedServices.filter(s => s !== serviceId)
      await apiPut('/api/adguard/blocked', { ids: newServices })
      blockedServices = newServices
      toast(blocked ? `${serviceId} blocked` : `${serviceId} unblocked`, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleSafeBrowsing(enabled) {
    try {
      await apiPost('/api/adguard/safebrowsing', { enabled })
      safeBrowsing = { ...safeBrowsing, enabled }
      toast(enabled ? 'Safe Browsing enabled' : 'Safe Browsing disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleParental(enabled) {
    try {
      await apiPost('/api/adguard/parental', { enabled })
      parental = { ...parental, enabled }
      toast(enabled ? 'Parental Control enabled' : 'Parental Control disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleSafeSearch(enabled) {
    try {
      await apiPost('/api/adguard/safesearch', { enabled })
      safeSearch = { ...safeSearch, enabled }
      toast(enabled ? 'Safe Search enabled' : 'Safe Search disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function addRewrite() {
    if (!newRewriteDomain || !newRewriteAnswer) return
    try {
      await apiPost('/api/adguard/rewrites', { domain: newRewriteDomain, answer: newRewriteAnswer })
      // Update local state
      rewrites = [...rewrites, { domain: newRewriteDomain, answer: newRewriteAnswer }]
      toast('Rewrite added', 'success')
      newRewriteDomain = ''
      newRewriteAnswer = ''
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function deleteRewrite(domain, answer) {
    try {
      await apiDelete('/api/adguard/rewrites', { domain, answer })
      toast('Rewrite deleted', 'success')
      loadedTabs.rewrites = false
      loadRewrites()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function setPresetFilter(name, url) {
    newFilterName = name
    newFilterUrl = url
  }

  function refreshCurrentTab() {
    loadedTabs[activeTab] = false
    if (activeTab === 'filters') loadFilters()
    else if (activeTab === 'rules') loadFilters()
    else if (activeTab === 'services') loadServices()
    else if (activeTab === 'safety') loadSafety()
    else if (activeTab === 'rewrites') loadRewrites()
    else loadCoreData()
  }

  onMount(loadCoreData)
</script>

<div class="space-y-4">
  <InfoCard
    icon="shield"
    title="AdGuard DNS"
    description="Network-wide ad blocking and privacy protection. Block ads, trackers, and malware at the DNS level for all VPN clients."
  />

  {#if loading}
    <LoadingSpinner size="lg" centered />
  {:else}
    <!-- Stats Grid -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <StatCard icon="activity" color="info" value={formatNumber(totalQueries)} label="DNS Queries" />
      <StatCard icon="ban" color="destructive" value={formatNumber(blockedQueries)} label="Blocked ({blockPercent}%)" />
      <StatCard icon="filter" color="primary" value={enabledFilters} label="Active Filters" />
      <StatCard icon="globe" color="warning" value={blockedServices.length} label="Blocked Services" />
    </div>

    <!-- Tabs (like Traefik) -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <div class="flex border-b border-border overflow-x-auto">
        {#each tabs as tab}
          <button
            onclick={() => activeTab = tab.id}
            class="flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors relative
              {activeTab === tab.id ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}"
          >
            <Icon name={tab.icon} size={16} />
            {tab.label}
            {#if activeTab === tab.id}
              <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"></div>
            {/if}
          </button>
        {/each}
      </div>

      <div class="p-5">
        <!-- Overview Tab -->
        {#if activeTab === 'overview'}
          <div class="space-y-6">
            <!-- Active Protections - 2 per row cards with toggle -->
            <div>
              <h4 class="text-sm font-semibold text-foreground mb-3">Active Protections</h4>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <!-- Safe Browsing -->
                <div class="p-4 rounded-lg border {safeBrowsing?.enabled ? 'border-success/30 bg-success/5' : 'border-border bg-muted/30'}">
                  <div class="flex items-start justify-between">
                    <div class="flex items-center gap-3">
                      <div class="w-10 h-10 rounded-lg flex items-center justify-center {safeBrowsing?.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                        <Icon name="shield" size={20} />
                      </div>
                      <div>
                        <div class="font-medium text-foreground">Safe Browsing</div>
                        <div class="text-xs text-muted-foreground">Block malware & phishing sites</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      class="kt-switch"
                      checked={safeBrowsing?.enabled}
                      onchange={() => toggleSafeBrowsing(!safeBrowsing?.enabled)}
                    />
                  </div>
                </div>

                <!-- Parental Control -->
                <div class="p-4 rounded-lg border {parental?.enabled ? 'border-success/30 bg-success/5' : 'border-border bg-muted/30'}">
                  <div class="flex items-start justify-between">
                    <div class="flex items-center gap-3">
                      <div class="w-10 h-10 rounded-lg flex items-center justify-center {parental?.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                        <Icon name="users" size={20} />
                      </div>
                      <div>
                        <div class="font-medium text-foreground">Parental Control</div>
                        <div class="text-xs text-muted-foreground">Block adult content</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      class="kt-switch"
                      checked={parental?.enabled}
                      onchange={() => toggleParental(!parental?.enabled)}
                    />
                  </div>
                </div>

                <!-- Safe Search -->
                <div class="p-4 rounded-lg border {safeSearch?.enabled ? 'border-success/30 bg-success/5' : 'border-border bg-muted/30'}">
                  <div class="flex items-start justify-between">
                    <div class="flex items-center gap-3">
                      <div class="w-10 h-10 rounded-lg flex items-center justify-center {safeSearch?.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                        <Icon name="search" size={20} />
                      </div>
                      <div>
                        <div class="font-medium text-foreground">Safe Search</div>
                        <div class="text-xs text-muted-foreground">Force safe search on engines</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      class="kt-switch"
                      checked={safeSearch?.enabled}
                      onchange={() => toggleSafeSearch(!safeSearch?.enabled)}
                    />
                  </div>
                </div>

                <!-- DNS Protection -->
                <div class="p-4 rounded-lg border {status?.protection_enabled ? 'border-success/30 bg-success/5' : 'border-border bg-muted/30'}">
                  <div class="flex items-start justify-between">
                    <div class="flex items-center gap-3">
                      <div class="w-10 h-10 rounded-lg flex items-center justify-center {status?.protection_enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                        <Icon name="shield-check" size={20} />
                      </div>
                      <div>
                        <div class="font-medium text-foreground">DNS Protection</div>
                        <div class="text-xs text-muted-foreground">Block ads, trackers & malware</div>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      class="kt-switch"
                      checked={status?.protection_enabled}
                      onchange={() => toggleProtection(!status?.protection_enabled)}
                    />
                  </div>
                </div>
              </div>
            </div>

            <!-- Blocked Services Section -->
            <div class="rounded-lg border border-border bg-card overflow-hidden">
              <div class="px-4 py-3 border-b border-border bg-muted/30">
                <div class="flex items-center justify-between">
                  <h4 class="text-sm font-semibold text-foreground">Blocked Services</h4>
                  {#if blockedServices.length > 0}
                    <span class="kt-badge kt-badge-danger kt-badge-sm">{blockedServices.length} blocked</span>
                  {/if}
                </div>
              </div>

              <div class="divide-y divide-border">
                {#each SERVICE_CATEGORIES as category, i}
                  {@const categoryServices = getServicesByCategory(category.id)}
                  {#if categoryServices.length > 0}
                    {@const blockedInCategory = categoryServices.filter(s => blockedServices.includes(typeof s === 'string' ? s : s.id)).length}
                    <div class="p-4">
                      <div class="flex items-center justify-between mb-3">
                        <span class="text-xs font-medium text-foreground">{category.name}</span>
                        <span class="text-[10px] text-muted-foreground">
                          {#if blockedInCategory > 0}
                            <span class="text-destructive">{blockedInCategory}</span> / {categoryServices.length}
                          {:else}
                            {categoryServices.length} services
                          {/if}
                        </span>
                      </div>
                      <div class="flex flex-wrap gap-2">
                        {#each categoryServices as service}
                          {@const serviceId = typeof service === 'string' ? service : service.id}
                          {@const serviceName = typeof service === 'string' ? service.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) : service.name}
                          {@const serviceIcon = typeof service === 'object' ? service.icon_svg : null}
                          {@const isBlocked = blockedServices.includes(serviceId)}
                          <button
                            onclick={() => toggleService(serviceId, !isBlocked)}
                            class="kt-badge cursor-pointer transition-colors {isBlocked ? 'kt-badge-danger' : 'kt-badge-outline hover:bg-muted'}"
                          >
                            {#if serviceIcon}
                              <img src="data:image/svg+xml;base64,{serviceIcon}" alt="" class="w-4 h-4 {isBlocked ? '' : 'opacity-60'}" />
                            {:else}
                              <Icon name="globe" size={16} class={isBlocked ? '' : 'opacity-60'} />
                            {/if}
                            {serviceName}
                          </button>
                        {/each}
                      </div>
                    </div>
                  {/if}
                {/each}
              </div>
            </div>
          </div>

        <!-- Filters Tab -->
        {:else if activeTab === 'filters'}
          {#if !loadedTabs.filters}
            <LoadingSpinner size="lg" centered />
          {:else}
            <!-- Summary bar -->
            <div class="flex items-center justify-between mb-4 pb-4 border-b border-border">
              <div class="flex items-center gap-4 text-sm">
                {#if filters.length > 0}
                  <span class="text-muted-foreground">{filters.filter(f => f.enabled).length} active</span>
                  <span class="text-muted-foreground">·</span>
                  <span class="text-muted-foreground">{formatNumber(filters.reduce((sum, f) => sum + (f.rules_count || 0), 0))} rules</span>
                {:else}
                  <span class="text-muted-foreground">No blocklists configured</span>
                {/if}
              </div>
              <div class="flex gap-2">
                {#if filters.length > 0}
                  <Button onclick={refreshFilters} variant="secondary" size="sm" icon="refresh">
                    Update
                  </Button>
                {/if}
                <Button onclick={() => showAddFilterModal = true} size="sm" icon="plus">
                  Add
                </Button>
              </div>
            </div>

            {#if filters.length === 0}
              <EmptyState
                icon="filter"
                title="No Filters"
                description="Add blocklists to start filtering DNS queries"
              />
            {:else}
              <!-- Filters grid -->
              <div class="grid grid-cols-2 lg:grid-cols-3 gap-3">
                {#each filters as filter}
                  <div class="rounded-lg border border-border bg-card overflow-hidden {!filter.enabled ? 'opacity-50' : ''}">
                    <div class="p-3">
                      <div class="flex items-start justify-between gap-2 mb-1">
                        <span class="text-sm font-medium text-foreground line-clamp-2 leading-tight">{filter.name}</span>
                        <input
                          type="checkbox"
                          class="kt-switch flex-shrink-0"
                          checked={filter.enabled}
                          onchange={() => toggleFilter(filter.url, filter.name, !filter.enabled)}
                        />
                      </div>
                      <span class="text-xs text-muted-foreground">{formatNumber(filter.rules_count)} rules</span>
                    </div>
                    <div class="flex items-center justify-between px-3 py-2 border-t border-border bg-muted/30">
                      <span class="text-[10px] text-muted-foreground">
                        {#if filter.last_updated}
                          Updated {new Date(filter.last_updated).toLocaleDateString()}
                        {:else}
                          —
                        {/if}
                      </span>
                      <Button
                        onclick={() => removeFilter(filter.url)}
                        variant="destructive"
                        size="sm"
                        iconOnly
                        icon="trash"
                        class="kt-btn-outline"
                        title="Remove"
                      />
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
          {/if}

        <!-- Block Rules Tab -->
        {:else if activeTab === 'rules'}
          {#if !loadedTabs.rules}
            <LoadingSpinner size="lg" centered />
          {:else}
            <!-- Add domain form -->
            <div class="flex items-center gap-3 mb-6 pb-4 border-b border-border">
              <Input
                type="text"
                bind:value={newBlockDomain}
                placeholder="Enter domain (e.g., facebook.com)"
                class="flex-1"
                onkeydown={(e) => {
                  if (e.key === 'Enter') handleAddBlockRule()
                }}
              />
              <div class="kt-toggle-group">
                <Button onclick={handleAddBlockRule} icon="ban">
                  Block
                </Button>
                <Button onclick={() => { newAllowDomain = newBlockDomain; newBlockDomain = ''; handleAddAllowRule() }} icon="check">
                  Allow
                </Button>
              </div>
            </div>

            <!-- Blocked Domains -->
            <div class="mb-6">
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <Icon name="ban" size={16} class="text-destructive" />
                  <span class="text-sm font-medium text-foreground">Blocked Domains</span>
                </div>
                <span class="text-xs text-muted-foreground">{blockedDomains.length} domains</span>
              </div>
              {#if blockedDomains.length > 0}
                <div class="flex flex-wrap gap-2 pb-4 mb-4 border-b border-border/20">
                  {#each blockedDomains as domain}
                    <span class="kt-badge kt-badge-danger">
                      <span class="font-mono">{domain}</span>
                      <button onclick={() => removeRule(`||${domain}^`)} class="ml-1 hover:text-destructive-foreground">
                        <Icon name="x" size={14} />
                      </button>
                    </span>
                  {/each}
                </div>
              {:else}
                <p class="text-sm text-muted-foreground pb-4 mb-4 border-b border-border/20">No blocked domains</p>
              {/if}
            </div>

            <!-- Allowed Domains -->
            <div>
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <Icon name="check" size={16} class="text-success" />
                  <span class="text-sm font-medium text-foreground">Allowed Domains</span>
                </div>
                <span class="text-xs text-muted-foreground">{allowedDomains.length} domains</span>
              </div>
              {#if allowedDomains.length > 0}
                <div class="flex flex-wrap gap-2">
                  {#each allowedDomains as domain}
                    <span class="kt-badge kt-badge-success">
                      <span class="font-mono">{domain}</span>
                      <button onclick={() => removeRule(`@@||${domain}^`)} class="ml-1 hover:text-success-foreground">
                        <Icon name="x" size={14} />
                      </button>
                    </span>
                  {/each}
                </div>
              {:else}
                <p class="text-sm text-muted-foreground">No allowed domains</p>
              {/if}
            </div>
          {/if}

        <!-- DNS Rewrites Tab -->
        {:else if activeTab === 'rewrites'}
          {#if !loadedTabs.rewrites}
            <LoadingSpinner size="lg" centered />
          {:else}
            <!-- Add rewrite form -->
            <div class="flex items-center gap-3 mb-6 pb-4 border-b border-border">
              <Input
                type="text"
                bind:value={newRewriteDomain}
                placeholder="Domain (e.g., example.local)"
                class="flex-1"
                onkeydown={(e) => e.key === 'Enter' && addRewrite()}
              />
              <Icon name="arrow-right" size={16} class="text-muted-foreground flex-shrink-0" />
              <Input
                type="text"
                bind:value={newRewriteAnswer}
                placeholder="Answer (IP or domain)"
                class="flex-1"
                onkeydown={(e) => e.key === 'Enter' && addRewrite()}
              />
              <Button onclick={addRewrite} size="sm" icon="plus">
                Add
              </Button>
            </div>

            <!-- Rewrites list -->
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center gap-2">
                <Icon name="link" size={16} class="text-info" />
                <span class="text-sm font-medium text-foreground">DNS Rewrites</span>
              </div>
              <span class="text-xs text-muted-foreground">{rewrites.length} rewrites</span>
            </div>

            {#if rewrites.length === 0}
              <p class="text-sm text-muted-foreground">No DNS rewrites configured</p>
            {:else}
              <div class="flex flex-wrap gap-2">
                {#each rewrites as rewrite}
                  <span class="kt-badge kt-badge-outline">
                    <span class="font-mono">{rewrite.domain}</span>
                    <Icon name="arrow-right" size={12} class="text-muted-foreground mx-1" />
                    <span class="font-mono text-primary">{rewrite.answer}</span>
                    <button onclick={() => deleteRewrite(rewrite.domain, rewrite.answer)} class="ml-1 hover:text-destructive">
                      <Icon name="x" size={14} />
                    </button>
                  </span>
                {/each}
              </div>
            {/if}
          {/if}
        {/if}
      </div>
    </div>
  {/if}
</div>

<!-- Add Filter Modal -->
<Modal bind:open={showAddFilterModal} title="Add Blocklist" size="lg">
  <!-- Mode tabs -->
  <div class="flex border-b border-border mb-4 -mt-2">
    <button
      onclick={() => addFilterMode = 'list'}
      class="px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors
        {addFilterMode === 'list' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
    >
      <Icon name="list" size={14} class="inline mr-1.5" />
      Choose from List
    </button>
    <button
      onclick={() => addFilterMode = 'manual'}
      class="px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors
        {addFilterMode === 'manual' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
    >
      <Icon name="edit" size={14} class="inline mr-1.5" />
      Add Manually
    </button>
  </div>

  {#if addFilterMode === 'list'}
    <div class="mb-4">
      <Input
        type="text"
        bind:value={filterSearchQuery}
        placeholder="Search blocklists..."
        prefixIcon="search"
      />
    </div>

    <div class="max-h-[400px] overflow-y-auto space-y-4 pr-2">
      {#each filteredBlocklists as category}
        <div>
          <h4 class="text-sm font-semibold text-foreground mb-1">{category.name}</h4>
          <p class="text-xs text-muted-foreground mb-2">{category.description}</p>
          <div class="space-y-1">
            {#each category.lists as list}
              {@const alreadyAdded = isListAlreadyAdded(list.url)}
              {@const isSelected = selectedLists.includes(list.id)}
              <label
                class="flex items-center gap-3 p-2 rounded-lg border transition-colors cursor-pointer
                  {alreadyAdded ? 'border-success/30 bg-success/5 opacity-60' : isSelected ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}"
              >
                <input
                  type="checkbox"
                  checked={isSelected || alreadyAdded}
                  disabled={alreadyAdded}
                  onchange={() => !alreadyAdded && toggleListSelection(list.id)}
                  class="w-4 h-4"
                />
                <div class="flex-1 min-w-0">
                  <div class="text-sm font-medium text-foreground">{list.name}</div>
                </div>
                {#if alreadyAdded}
                  <Badge variant="success" size="sm">Added</Badge>
                {/if}
              </label>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <div class="space-y-4">
      <Input
        label="Filter Name"
        bind:value={newFilterName}
        placeholder="e.g., My Custom Blocklist"
      />
      <Input
        label="Filter URL"
        helperText="Enter a URL to a hosts file or AdBlock-style filter list"
        bind:value={newFilterUrl}
        placeholder="https://example.com/blocklist.txt"
      />
    </div>
  {/if}

  {#snippet footer()}
    {#if addFilterMode === 'list'}
      <span class="text-sm text-muted-foreground mr-auto">{selectedLists.length} selected</span>
      <Button onclick={() => { showAddFilterModal = false; selectedLists = []; filterSearchQuery = '' }} variant="secondary">Cancel</Button>
      <Button onclick={addFilter} disabled={selectedLists.length === 0}>
        Add {selectedLists.length} Blocklist{selectedLists.length !== 1 ? 's' : ''}
      </Button>
    {:else}
      <Button onclick={() => showAddFilterModal = false} variant="secondary">Cancel</Button>
      <Button onclick={addFilter} disabled={!newFilterName || !newFilterUrl}>Add Filter</Button>
    {/if}
  {/snippet}
</Modal>

