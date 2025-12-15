<script>
  import { onMount } from 'svelte'
  import { toast, apiGet } from '../stores/app.js'
  import { formatTime } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'

  let { loading = $bindable(true) } = $props()

  let queryLog = $state([])
  let search = $state('')

  // Get status info from AdGuard reason
  function getStatusInfo(log) {
    const reason = log.reason || ''
    const rules = log.rules || []
    const serviceName = rules.find(r => r.filter_list_id === -1)?.text || ''

    switch (reason) {
      case 'NotFilteredNotFound':
      case 'NotFilteredAllowList':
        return { label: 'Processed', variant: 'success' }
      case 'NotFilteredWhiteList':
        return { label: 'Allowed', variant: 'success' }
      case 'NotFilteredError':
        return { label: 'Error', variant: 'warning' }
      case 'FilteredBlockList':
        return { label: 'Blocked', variant: 'danger' }
      case 'FilteredSafeBrowsing':
        return { label: 'Blocked Threats', variant: 'danger' }
      case 'FilteredParental':
        return { label: 'Blocked by Parental', variant: 'danger' }
      case 'FilteredBlockedService':
        return { label: serviceName ? `Blocked (${serviceName})` : 'Blocked Service', variant: 'danger' }
      case 'FilteredSafeSearch':
        return { label: 'Safe Search', variant: 'info' }
      case 'Rewrite':
      case 'RewriteEtcHosts':
      case 'RewriteRule':
        return { label: 'Rewritten', variant: 'info' }
      default:
        if (reason.startsWith('Filtered')) {
          return { label: 'Filtered', variant: 'warning' }
        }
        return { label: reason || 'Unknown', variant: 'secondary' }
    }
  }

  async function loadLogs() {
    try {
      const res = await apiGet('/api/adguard/querylog?limit=100')
      queryLog = res?.data || []
    } catch (e) {
      toast('Failed to load logs: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  const filteredLogs = $derived(
    queryLog.filter(log => {
      if (!search) return true
      const q = search.toLowerCase()
      return (
        log.question?.name?.toLowerCase().includes(q) ||
        log.client?.toLowerCase().includes(q) ||
        log.question?.type?.toLowerCase().includes(q)
      )
    })
  )

  onMount(loadLogs)
</script>

<div class="space-y-4">
  <InfoCard
    icon="list"
    title="AdGuard Query Log"
    description="View DNS queries from VPN clients. See which domains are being accessed and blocked by AdGuard."
  />

  <Toolbar bind:search placeholder="Search domains, clients...">
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
      icon="list"
      title="No DNS Queries"
      description={search ? 'No results match your search' : 'Waiting for VPN clients to make DNS requests...'}
    />
  {:else}
    <div class="kt-table-wrapper rounded-xl border border-border bg-card overflow-hidden">
      <table class="kt-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Client</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredLogs as log}
            {@const status = getStatusInfo(log)}
            <tr>
              <td class="whitespace-nowrap">{formatTime(log.time)}</td>
              <td>
                <code class="text-xs font-mono text-muted-foreground">{log.client || '-'}</code>
              </td>
              <td>
                <code class="text-xs font-mono {status.variant === 'danger' ? 'text-destructive' : ''}">{log.question?.name || '-'}</code>
              </td>
              <td>
                <Badge variant="info" size="sm">{log.question?.type || 'A'}</Badge>
              </td>
              <td>
                <Badge variant={status.variant} size="sm">
                  {status.label}
                </Badge>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
