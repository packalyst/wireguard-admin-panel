<script>
  import { onMount } from 'svelte'
  import { toast, apiGet } from '../stores/app.js'
  import { formatDuration, formatTime } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'

  let { loading = $bindable(true) } = $props()

  let accessLogs = $state([])
  let search = $state('')

  async function loadLogs() {
    try {
      accessLogs = await apiGet('/api/traefik/logs?limit=100')
    } catch (e) {
      toast('Failed to load logs: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  const filteredLogs = $derived(
    accessLogs.filter(log => {
      if (!search) return true
      const q = search.toLowerCase()
      return (
        log.path?.toLowerCase().includes(q) ||
        log.clientIP?.toLowerCase().includes(q) ||
        log.method?.toLowerCase().includes(q) ||
        String(log.status).includes(q)
      )
    })
  )

  onMount(loadLogs)
</script>

<div class="space-y-4">
  <InfoCard
    icon="file-text"
    title="Traefik Access Logs"
    description="View recent HTTP requests passing through Traefik reverse proxy. Monitor response times and status codes."
  />

  <Toolbar bind:search placeholder="Search path, client IP, method...">
    <span
      onclick={loadLogs}
      class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
    >
      <Icon name="refresh" size={14} />
      Refresh
    </span>
  </Toolbar>

  {#if loading}
    <LoadingSpinner size="lg" centered />
  {:else if filteredLogs.length === 0}
    <EmptyState
      icon="file-text"
      title="No Logs Yet"
      description={search ? 'No results match your search' : 'Access logs will appear when requests are made'}
    />
  {:else}
    <div class="kt-table-wrapper rounded-xl border border-border bg-card overflow-hidden">
      <table class="kt-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Method</th>
            <th>Path</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Client</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredLogs as log}
            <tr>
              <td class="whitespace-nowrap">{formatTime(log.time)}</td>
              <td>
                <Badge variant={log.method === 'GET' ? 'info' : log.method === 'POST' ? 'success' : 'muted'} size="sm">
                  {log.method}
                </Badge>
              </td>
              <td>
                <code class="text-xs font-mono">{log.path}</code>
              </td>
              <td>
                <Badge variant={log.status < 300 ? 'success' : log.status < 400 ? 'info' : 'danger'} size="sm">
                  {log.status}
                </Badge>
              </td>
              <td>{formatDuration(log.duration)}</td>
              <td>
                <code class="text-xs font-mono text-muted-foreground">{log.clientIP}</code>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
