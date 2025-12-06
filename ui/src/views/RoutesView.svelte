<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiDelete } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'

  let { loading = $bindable(true) } = $props()

  let routes = $state([])
  let nodes = $state([])
  let pollInterval = null

  async function loadData() {
    try {
      const [routesRes, nodesRes] = await Promise.all([
        apiGet('/api/hs/routes'),
        apiGet('/api/hs/nodes')
      ])
      routes = routesRes.routes || []
      nodes = nodesRes.nodes || []
    } catch (e) {
      toast('Failed to load routes: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  onMount(() => {
    loadData()
    pollInterval = setInterval(loadData, 30000)
  })

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval)
  })

  let showDeleteModal = $state(false)
  let deletingRoute = $state(null)
  let searchQuery = $state('')

  // Get node info for a route
  function getNodeForRoute(route) {
    return nodes.find(n => n.id === route.node?.id || n.id === route.machineId)
  }

  // Check if route is exit node
  function isExitNode(prefix) {
    return prefix === '0.0.0.0/0' || prefix === '::/0'
  }

  // Process routes: combine exit node pairs (IPv4 + IPv6) into single entries
  const processedRoutes = $derived(() => {
    const result = []
    const exitNodesByNode = new Map() // Group exit nodes by node ID

    for (const route of routes) {
      if (isExitNode(route.prefix)) {
        const nodeId = route.node?.id || route.machineId
        if (!exitNodesByNode.has(nodeId)) {
          exitNodesByNode.set(nodeId, { ipv4: null, ipv6: null })
        }
        if (route.prefix === '0.0.0.0/0') {
          exitNodesByNode.get(nodeId).ipv4 = route
        } else {
          exitNodesByNode.get(nodeId).ipv6 = route
        }
      } else {
        // Regular subnet route
        result.push({ ...route, isExitNode: false, combined: false })
      }
    }

    // Add combined exit nodes
    for (const [nodeId, pair] of exitNodesByNode) {
      const primaryRoute = pair.ipv4 || pair.ipv6
      if (primaryRoute) {
        result.push({
          ...primaryRoute,
          prefix: 'Exit Node',
          isExitNode: true,
          combined: true,
          ipv4Route: pair.ipv4,
          ipv6Route: pair.ipv6,
          // Use IPv4 route for toggle/delete, both get affected anyway
          id: pair.ipv4?.id || pair.ipv6?.id,
          enabled: (pair.ipv4?.enabled || false) || (pair.ipv6?.enabled || false)
        })
      }
    }

    return result
  })

  // Filtered routes
  const filteredRoutes = $derived(
    processedRoutes().filter(r =>
      r.prefix?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.node?.givenName?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.node?.name?.toLowerCase().includes(searchQuery.toLowerCase())
    )
  )

  async function toggleRoute(route) {
    try {
      const action = route.enabled ? 'disable' : 'enable'
      await apiPost(`/api/hs/routes/${route.id}/${action}`)
      toast(`Route ${route.enabled ? 'disabled' : 'enabled'}`, 'success')
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function confirmDelete(route) {
    deletingRoute = route
    showDeleteModal = true
  }

  async function deleteRoute() {
    if (!deletingRoute) return
    try {
      // For combined exit nodes, delete both routes
      if (deletingRoute.combined) {
        if (deletingRoute.ipv4Route) {
          await apiDelete(`/api/hs/routes/${deletingRoute.ipv4Route.id}`)
        }
        if (deletingRoute.ipv6Route) {
          await apiDelete(`/api/hs/routes/${deletingRoute.ipv6Route.id}`)
        }
      } else {
        await apiDelete(`/api/hs/routes/${deletingRoute.id}`)
      }
      toast('Route deleted', 'success')
      showDeleteModal = false
      deletingRoute = null
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Get status label
  function getStatusInfo(route) {
    if (!route.advertised) {
      return { label: 'Not Advertised', variant: 'muted' }
    }
    if (route.enabled) {
      return { label: 'Enabled', variant: 'success' }
    }
    return { label: 'Pending', variant: 'warning' }
  }
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="route" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Network Routes</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Configure subnet routes and exit nodes advertised by your network nodes. Enable routes
          to allow traffic to flow through specific nodes to reach internal networks or the internet.
        </p>
      </div>
    </div>
  </div>

  {#if routes.length > 0}
    <!-- Toolbar -->
    <Toolbar bind:search={searchQuery} placeholder="Search routes...">
      <span class="text-sm text-muted-foreground">{filteredRoutes.length} routes</span>
    </Toolbar>

    <!-- Routes Table -->
    {#if filteredRoutes.length > 0}
      <div class="bg-card border border-border rounded-xl overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-muted/50">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Approval</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Route</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Type</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Node</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Primary</th>
              <th class="px-4 py-3 w-24"></th>
            </tr>
          </thead>
          <tbody>
            {#each filteredRoutes as route}
              {@const node = route.node || getNodeForRoute(route)}
              {@const status = getStatusInfo(route)}
              <tr class="border-t border-border hover:bg-accent/50">
                <td class="px-4 py-3">
                  <Badge variant={status.variant} size="sm">
                    {status.label}
                  </Badge>
                </td>
                <td class="px-4 py-3">
                  {#if route.enabled}
                    <Badge variant="success" size="sm">Approved</Badge>
                  {:else}
                    <Badge variant="warning" size="sm">Awaiting</Badge>
                  {/if}
                </td>
                <td class="px-4 py-3">
                  {#if route.isExitNode}
                    <div class="flex items-center gap-2">
                      <Icon name="globe" size={14} class="text-primary" />
                      <span class="font-medium text-foreground">Exit Node</span>
                    </div>
                    <div class="text-xs text-muted-foreground mt-0.5">
                      IPv4 + IPv6 (all traffic)
                    </div>
                  {:else}
                    <code class="text-sm font-mono font-medium text-foreground">{route.prefix}</code>
                  {/if}
                </td>
                <td class="px-4 py-3">
                  <Badge variant={route.isExitNode ? 'primary' : 'info'} size="sm">
                    {route.isExitNode ? 'Exit' : 'Subnet'}
                  </Badge>
                </td>
                <td class="px-4 py-3">
                  <span class="text-foreground">{node?.givenName || node?.name || '—'}</span>
                </td>
                <td class="px-4 py-3">
                  {#if route.isPrimary}
                    <Badge variant="warning" size="sm">Yes</Badge>
                  {:else}
                    <span class="text-muted-foreground">—</span>
                  {/if}
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center justify-end gap-1">
                    <button
                      onclick={() => toggleRoute(route)}
                      class="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                      title={route.enabled ? 'Disable route' : 'Enable route'}
                    >
                      <Icon name={route.enabled ? 'x' : 'check'} size={14} />
                    </button>
                    <button
                      onclick={() => confirmDelete(route)}
                      class="p-1.5 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                      title="Delete route"
                    >
                      <Icon name="trash" size={14} />
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <!-- No search results -->
      <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
        <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
          <Icon name="search" size={20} />
        </div>
        <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No routes found</h4>
        <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Try a different search term</p>
      </div>
    {/if}
  {:else}
    <!-- Empty State -->
    <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
      <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
        <Icon name="route" size={20} />
      </div>
      <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No routes</h4>
      <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Routes appear when nodes advertise subnets or exit nodes</p>
    </div>
  {/if}
</div>

<!-- Delete Confirmation Modal -->
<Modal bind:open={showDeleteModal} title="Delete Route" size="sm">
  {#if deletingRoute}
    <div class="text-center">
      <div class="w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center mx-auto mb-4">
        <Icon name="alert-triangle" size={24} class="text-destructive" />
      </div>
      <p class="text-foreground mb-2">
        {#if deletingRoute.isExitNode}
          Remove <strong>Exit Node</strong> from <strong>{deletingRoute.node?.givenName || deletingRoute.node?.name}</strong>?
        {:else}
          Delete route <strong class="font-mono">{deletingRoute.prefix}</strong>?
        {/if}
      </p>
      <p class="text-sm text-muted-foreground">
        {#if deletingRoute.isExitNode}
          This will remove both IPv4 and IPv6 exit routes.
        {:else}
          This action cannot be undone.
        {/if}
      </p>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => { showDeleteModal = false; deletingRoute = null }} variant="secondary">Cancel</Button>
    <Button onclick={deleteRoute} variant="destructive">Delete</Button>
  {/snippet}
</Modal>
