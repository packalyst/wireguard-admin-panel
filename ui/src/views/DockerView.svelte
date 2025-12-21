<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  let { loading = $bindable(true) } = $props()

  let containers = $state([])
  let pollInterval = null

  // Logs modal state
  let showLogsModal = $state(false)
  let logsContainer = $state(null)
  let logs = $state([])
  let loadingLogs = $state(false)
  let logsAutoScroll = $state(true)

  // Action states
  let actionInProgress = $state(null)

  async function loadData() {
    try {
      const res = await apiGet('/api/docker/containers')
      containers = res.containers || []
    } catch (e) {
      toast('Failed to load containers: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  onMount(() => {
    loadData()
    pollInterval = setInterval(loadData, 10000)
  })

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval)
  })

  // Get state color
  function getStateVariant(state) {
    if (state === 'running') return 'success'
    if (state === 'exited') return 'danger'
    if (state === 'restarting') return 'warning'
    return 'muted'
  }

  // Get icon for container
  function getContainerIcon(name) {
    const icons = {
      'traefik': 'route',
      'headscale': 'network',
      'api': 'server',
      'adguard': 'shield',
      'ui-dev': 'layout'
    }
    return icons[name] || 'box'
  }

  // Format uptime
  function formatUptime(status) {
    return status || 'Unknown'
  }

  // Actions
  async function restartContainer(name) {
    actionInProgress = name + '-restart'
    try {
      await apiPost(`/api/docker/containers/${name}/restart`)
      toast(`Container ${name} restarted`, 'success')
      loadData()
    } catch (e) {
      toast('Failed to restart: ' + e.message, 'error')
    } finally {
      actionInProgress = null
    }
  }

  async function stopContainer(name) {
    actionInProgress = name + '-stop'
    try {
      await apiPost(`/api/docker/containers/${name}/stop`)
      toast(`Container ${name} stopped`, 'success')
      loadData()
    } catch (e) {
      toast('Failed to stop: ' + e.message, 'error')
    } finally {
      actionInProgress = null
    }
  }

  async function startContainer(name) {
    actionInProgress = name + '-start'
    try {
      await apiPost(`/api/docker/containers/${name}/start`)
      toast(`Container ${name} started`, 'success')
      loadData()
    } catch (e) {
      toast('Failed to start: ' + e.message, 'error')
    } finally {
      actionInProgress = null
    }
  }

  async function viewLogs(container) {
    logsContainer = container
    showLogsModal = true
    loadingLogs = true
    logs = []

    try {
      const res = await apiGet(`/api/docker/containers/${container.name}/logs?tail=200`)
      logs = res.logs || []
    } catch (e) {
      toast('Failed to load logs: ' + e.message, 'error')
    } finally {
      loadingLogs = false
    }
  }

  async function refreshLogs() {
    if (!logsContainer) return
    loadingLogs = true
    try {
      const res = await apiGet(`/api/docker/containers/${logsContainer.name}/logs?tail=200`)
      logs = res.logs || []
    } catch (e) {
      toast('Failed to refresh logs: ' + e.message, 'error')
    } finally {
      loadingLogs = false
    }
  }

  // Stats
  const runningCount = $derived(containers.filter(c => c.state === 'running').length)
  const stoppedCount = $derived(containers.filter(c => c.state !== 'running').length)
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="box" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Container Management</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Monitor and manage Docker containers. Restart services, view logs, and check container health.
        </p>
      </div>
    </div>
  </div>

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <!-- Stats -->
    <div class="grid grid-cols-3 gap-3">
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-info/10 flex items-center justify-center flex-shrink-0">
          <Icon name="box" size={20} class="text-info" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{containers.length}</div>
          <div class="text-[11px] text-muted-foreground">Total</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center flex-shrink-0">
          <Icon name="check" size={20} class="text-success" />
        </div>
        <div>
          <div class="text-2xl font-bold text-success">{runningCount}</div>
          <div class="text-[11px] text-muted-foreground">Running</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-danger/10 flex items-center justify-center flex-shrink-0">
          <Icon name="x" size={20} class="text-danger" />
        </div>
        <div>
          <div class="text-2xl font-bold text-danger">{stoppedCount}</div>
          <div class="text-[11px] text-muted-foreground">Stopped</div>
        </div>
      </div>
    </div>

    <!-- Containers List -->
    {#if containers.length > 0}
      <div class="space-y-2">
        {#each containers as container}
          <div class="bg-card border border-border rounded-lg px-4 py-3 hover:border-primary/30 transition-colors">
            <div class="flex flex-wrap sm:flex-nowrap items-center gap-3 sm:gap-4">
              <!-- Icon + Name -->
              <div class="flex items-center gap-3 min-w-0 flex-1 sm:flex-none sm:min-w-[200px]">
                <div class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 {container.state === 'running' ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                  <Icon name={getContainerIcon(container.name)} size={16} />
                </div>
                <div class="min-w-0">
                  <h3 class="font-medium text-sm text-foreground">{container.name}</h3>
                  <p class="text-[11px] text-muted-foreground truncate">{container.image.split(':')[0].split('/').pop()}</p>
                </div>
              </div>

              <!-- Mobile: Status + Actions aligned right -->
              <div class="flex flex-col items-end gap-1.5 sm:hidden">
                <Badge variant={getStateVariant(container.state)} size="sm">
                  {container.state}
                </Badge>
                <div class="btn-group">
                  <button onclick={() => viewLogs(container)} class="custom_btns" data-kt-tooltip>
                    <Icon name="file-text" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Logs</span>
                  </button>
                  {#if container.state === 'running'}
                    <button onclick={() => restartContainer(container.name)} disabled={actionInProgress === container.name + '-restart'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-restart'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="refresh" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Restart</span>
                    </button>
                    <button onclick={() => stopContainer(container.name)} disabled={actionInProgress === container.name + '-stop'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-stop'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-stop" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Stop</span>
                    </button>
                  {:else}
                    <button onclick={() => startContainer(container.name)} disabled={actionInProgress === container.name + '-start'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-start'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-play" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Start</span>
                    </button>
                  {/if}
                </div>
              </div>

              <!-- Desktop: Inline layout -->
              <div class="hidden sm:contents">
                <!-- Status -->
                <Badge variant={getStateVariant(container.state)} size="sm">
                  {container.state}
                </Badge>

                <!-- Uptime -->
                <span class="text-xs text-muted-foreground">
                  {formatUptime(container.status)}
                </span>

                <!-- Ports -->
                {#if container.ports?.length > 0}
                  {@const visiblePorts = container.ports.filter(p => p.publicPort)}
                  <div class="hidden md:flex items-center gap-1">
                    {#each visiblePorts.slice(0, 2) as port}
                      <span class="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                        :{port.publicPort}
                      </span>
                    {/each}
                    {#if visiblePorts.length > 2}
                      <span class="text-[10px] text-muted-foreground cursor-help" data-kt-tooltip>
                        +{visiblePorts.length - 2}
                        <span data-kt-tooltip-content class="kt-tooltip hidden">
                          {visiblePorts.slice(2).map(p => `:${p.publicPort}`).join(', ')}
                        </span>
                      </span>
                    {/if}
                  </div>
                {/if}

                <!-- Spacer -->
                <div class="flex-1"></div>

                <!-- Actions -->
                <div class="btn-group">
                  <button onclick={() => viewLogs(container)} class="custom_btns" data-kt-tooltip>
                    <Icon name="file-text" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Logs</span>
                  </button>
                  {#if container.state === 'running'}
                    <button onclick={() => restartContainer(container.name)} disabled={actionInProgress === container.name + '-restart'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-restart'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="refresh" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Restart</span>
                    </button>
                    <button onclick={() => stopContainer(container.name)} disabled={actionInProgress === container.name + '-stop'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-stop'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-stop" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Stop</span>
                    </button>
                  {:else}
                    <button onclick={() => startContainer(container.name)} disabled={actionInProgress === container.name + '-start'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-start'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-play" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Start</span>
                    </button>
                  {/if}
                </div>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {:else}
      <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
        <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
          <Icon name="box" size={20} />
        </div>
        <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No containers</h4>
        <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">No project containers found</p>
      </div>
    {/if}
  {/if}
</div>

<!-- Logs Modal -->
<Modal bind:open={showLogsModal} title="{logsContainer?.name} Logs" size="lg">
  <div class="space-y-3">
    <div class="flex items-center justify-between">
      <div class="text-sm text-muted-foreground">Last 200 lines</div>
      <Button onclick={refreshLogs} variant="secondary" size="sm" icon="refresh" disabled={loadingLogs}>
        Refresh
      </Button>
    </div>

    <div class="bg-zinc-900 rounded-lg p-3 max-h-[400px] overflow-auto font-mono text-xs">
      {#if loadingLogs && logs.length === 0}
        <div class="flex items-center justify-center py-8 text-zinc-500">
          <div class="w-5 h-5 border-2 border-zinc-500 border-t-transparent rounded-full animate-spin mr-2"></div>
          Loading logs...
        </div>
      {:else if logs.length === 0}
        <div class="text-zinc-500 text-center py-8">No logs available</div>
      {:else}
        {#each logs as log}
          <div class="text-zinc-300 hover:bg-zinc-800 px-1 py-0.5 rounded">
            {#if log.timestamp}
              <span class="text-zinc-500">{log.timestamp.substring(11, 19)}</span>
            {/if}
            <span class="ml-2">{log.message}</span>
          </div>
        {/each}
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={() => showLogsModal = false} variant="secondary">Close</Button>
  {/snippet}
</Modal>
