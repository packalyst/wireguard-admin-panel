<script>
  import { onMount, onDestroy, untrack } from 'svelte'
  import { subscribe, unsubscribe, statsStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import Chart from '../components/Chart.svelte'
  import InfoCard from '../components/InfoCard.svelte'

  let { loading = $bindable(true) } = $props()

  // Traffic history for chart (last 60 data points = 10 minutes at 10s intervals)
  let historyLabels = []
  let historyTx = []
  let historyRx = []
  const maxDataPoints = 60

  // Chart data counter to trigger updates
  let chartUpdateCounter = $state(0)

  // Build chart data on demand (not reactive to avoid proxy issues)
  function getChartData() {
    return {
      labels: [...historyLabels],
      datasets: [
        {
          label: 'Upload',
          data: [...historyTx],
          borderColor: 'rgb(34, 197, 94)',
          backgroundColor: 'rgba(34, 197, 94, 0.15)',
          fill: 'origin',
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 4,
          pointHoverBackgroundColor: 'rgb(34, 197, 94)',
          pointHoverBorderColor: '#fff',
          pointHoverBorderWidth: 2
        },
        {
          label: 'Download',
          data: [...historyRx],
          borderColor: 'rgb(99, 102, 241)',
          backgroundColor: 'rgba(99, 102, 241, 0.15)',
          fill: 'origin',
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 4,
          pointHoverBackgroundColor: 'rgb(99, 102, 241)',
          pointHoverBorderColor: '#fff',
          pointHoverBorderWidth: 2
        }
      ]
    }
  }

  // Reactive chart data that rebuilds when counter changes
  const chartData = $derived.by(() => {
    // Access counter to create dependency
    void chartUpdateCounter
    return getChartData()
  })

  // Format bytes to human readable
  function formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i]
  }

  // Format uptime to human readable
  function formatUptime(seconds) {
    if (!seconds) return '0s'
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    if (days > 0) return `${days}d ${hours}h`
    if (hours > 0) return `${hours}h ${mins}m`
    return `${mins}m ${seconds % 60}s`
  }

  // Format rate to human readable
  function formatRate(bytesPerSec) {
    return formatBytes(bytesPerSec) + '/s'
  }

  // Update traffic history with new data
  function updateTrafficHistory(stats) {
    if (!stats?.traffic) return

    const now = new Date()
    const timeLabel = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })

    // Update plain arrays
    historyLabels = [...historyLabels, timeLabel].slice(-maxDataPoints)
    historyTx = [...historyTx, stats.traffic.rate_tx || 0].slice(-maxDataPoints)
    historyRx = [...historyRx, stats.traffic.rate_rx || 0].slice(-maxDataPoints)

    // Trigger chart update
    chartUpdateCounter++
  }

  // Chart options
  const chartOptions = {
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          callback: (value) => formatBytes(value) + '/s'
        }
      },
      x: {
        ticks: {
          maxTicksLimit: 6
        }
      }
    },
    plugins: {
      tooltip: {
        callbacks: {
          label: (context) => `${context.dataset.label}: ${formatRate(context.raw)}`
        }
      }
    }
  }

  // Subscribe to stats updates
  $effect(() => {
    const stats = $statsStore
    if (stats) {
      untrack(() => {
        updateTrafficHistory(stats)
      })
      loading = false
    }
  })

  onMount(() => {
    subscribe('stats')
    loading = false
  })

  onDestroy(() => {
    unsubscribe('stats')
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="dashboard"
    title="Overview"
    description="System status, VPN traffic, and resource usage at a glance."
  />

  <!-- System Stats -->
  <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-primary/10">
            <Icon name="clock" size={20} class="text-primary" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Uptime</div>
            <div class="text-lg font-semibold">{formatUptime($statsStore?.system?.uptime)}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-info/10">
            <Icon name="cpu" size={20} class="text-info" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Memory</div>
            <div class="text-lg font-semibold">{formatBytes($statsStore?.system?.mem_alloc)}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-warning/10">
            <Icon name="activity" size={20} class="text-warning" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Goroutines</div>
            <div class="text-lg font-semibold">{$statsStore?.system?.num_goroutine || 0}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-success/10">
            <Icon name="users" size={20} class="text-success" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Nodes Online</div>
            <div class="text-lg font-semibold">{$statsStore?.nodes?.online || 0}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-destructive/10">
            <Icon name="user-off" size={20} class="text-destructive" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Nodes Offline</div>
            <div class="text-lg font-semibold">{$statsStore?.nodes?.offline || 0}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-secondary/10">
            <Icon name="plug-connected" size={20} class="text-muted-foreground" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">WS Clients</div>
            <div class="text-lg font-semibold">{$statsStore?.system?.ws_clients || 0}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Traffic Chart -->
  <div class="kt-panel">
    <div class="kt-panel-header">
      <h3 class="kt-panel-title">Network Traffic</h3>
      <div class="flex items-center gap-4 text-sm">
        <div class="flex items-center gap-2">
          <div class="w-2.5 h-2.5 rounded-full" style="background: rgb(34, 197, 94)"></div>
          <span class="text-muted-foreground">Upload: <span class="text-foreground font-medium">{formatRate($statsStore?.traffic?.rate_tx)}</span></span>
        </div>
        <div class="flex items-center gap-2">
          <div class="w-2.5 h-2.5 rounded-full" style="background: rgb(99, 102, 241)"></div>
          <span class="text-muted-foreground">Download: <span class="text-foreground font-medium">{formatRate($statsStore?.traffic?.rate_rx)}</span></span>
        </div>
      </div>
    </div>
    <div class="kt-panel-body">
      <div class="h-64">
        <Chart type="line" data={chartData} options={chartOptions} class="h-full" />
      </div>
    </div>
  </div>

  <!-- Traffic Totals & Top Peers -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <!-- Traffic Totals -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">Total Transfer</h3>
      </div>
      <div class="kt-panel-body">
        <div class="grid grid-cols-2 gap-4">
          <div class="p-4 rounded-lg bg-success/10 border border-success/20">
            <div class="flex items-center gap-2 mb-2">
              <Icon name="arrow-up" size={18} class="text-success" />
              <span class="text-sm text-muted-foreground">Uploaded</span>
            </div>
            <div class="text-2xl font-bold text-success">{formatBytes($statsStore?.traffic?.total_tx)}</div>
          </div>
          <div class="p-4 rounded-lg bg-info/10 border border-info/20">
            <div class="flex items-center gap-2 mb-2">
              <Icon name="arrow-down" size={18} class="text-info" />
              <span class="text-sm text-muted-foreground">Downloaded</span>
            </div>
            <div class="text-2xl font-bold text-info">{formatBytes($statsStore?.traffic?.total_rx)}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Top Peers by Traffic -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">Top Peers by Traffic</h3>
      </div>
      <div class="kt-panel-body">
        {#if $statsStore?.traffic?.by_peer?.length > 0}
          <div class="space-y-2">
            {#each $statsStore.traffic.by_peer.slice(0, 5) as peer}
              <div class="flex items-center justify-between p-2 rounded-lg bg-muted/50">
                <div class="flex items-center gap-3">
                  <Icon name="device-laptop" size={18} class="text-primary" />
                  <div>
                    <div class="font-medium text-sm">{peer.name}</div>
                    <div class="text-xs text-muted-foreground">{peer.ip}</div>
                  </div>
                </div>
                <div class="text-right">
                  <div class="text-xs">
                    <span class="text-success">{formatBytes(peer.tx)}</span>
                    <span class="text-muted-foreground"> / </span>
                    <span class="text-info">{formatBytes(peer.rx)}</span>
                  </div>
                </div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-center text-muted-foreground py-8">
            <Icon name="chart-bar" size={32} class="mx-auto mb-2 opacity-50" />
            <p class="text-sm">No traffic data yet</p>
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>
