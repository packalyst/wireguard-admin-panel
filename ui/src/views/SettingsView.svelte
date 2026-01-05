<script>
  import { onMount } from 'svelte'
  import { theme, toast, apiGet, apiPost, apiPut, apiDelete, generateAdguardCredentials } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Badge from '../components/Badge.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import Checkbox from '../components/Checkbox.svelte'

  let { loading = $bindable(true) } = $props()
  let savingAdguard = $state(false)
  let savingSession = $state(false)
  let savingTraefik = $state(false)
  let regeneratingKey = $state(false)

  // VPN Router state
  let routerStatus = $state(null)
  let routerLoading = $state(false)

  // Headscale settings
  let headscaleApiUrl = $state('')  // Internal API URL (readonly)
  let headscaleUrl = $state('')     // Public URL (editable)
  let headscaleHasKey = $state(false)
  let headscaleUrlChanged = $state(false)
  let savingHeadscale = $state(false)
  let originalHeadscaleUrl = ''

  // AdGuard settings
  let adguardUsername = $state('')
  let adguardPassword = $state('')
  let adguardDashboardEnabled = $state(true)
  let adguardDashboardURL = $state('')
  let adguardChanged = $state(false)

  // Traefik settings
  let traefikForm = $state({
    rateLimitAverage: 100,
    rateLimitBurst: 200,
    strictRateAverage: 10,
    strictRateBurst: 20,
    ipAllowlist: [],
    newIP: '',
    dashboardEnabled: true
  })
  let originalTraefik = $state(null)

  // VPN-only mode: "off", "403", or "silent"
  let vpnOnlyMode = $state('off')
  let vpnOnlyLoading = $state(false)

  // Session settings
  let sessionTimeout = $state('24')
  let sessionChanged = $state(false)

  // Scanner settings
  let scannerSettings = $state({
    portStart: 1,
    portEnd: 5000,
    concurrent: 100,
    pauseMs: 10,
    timeoutMs: 500
  })
  let originalScanner = $state(null)
  let savingScanner = $state(false)

  // UI settings (stored in localStorage)
  let itemsPerPage = $state('25')

  // Geolocation settings
  let geoSettings = $state({
    lookup_provider: 'none',
    blocking_enabled: false,
    auto_update: false,
    update_hour: 3,
    update_services: 'all',
    maxmind_license_key: '',
    ip2location_token: '',
    ip2location_variant: 'DB1'
  })
  let geoStatus = $state(null)
  let geoProviders = $state(null)  // Provider configs from API
  let loadingGeo = $state(false)
  let savingGeo = $state(false)
  let originalGeoSettings = $state(null)
  let triggeringGeoUpdate = $state(false)

  // Original values for change detection
  let originalAdguard = { username: '', password: '', dashboardEnabled: true }
  let originalSession = { timeout: '24' }

  async function loadSettings() {
    loading = true
    try {
      const [settings, traefikConfig, vpnOnlyStatus] = await Promise.all([
        apiGet('/api/settings'),
        apiGet('/api/traefik/config').catch(() => null),
        apiGet('/api/traefik/vpn-only').catch(() => ({ enabled: false }))
      ])

      // VPN-only mode
      vpnOnlyMode = vpnOnlyStatus?.mode || 'off'

      // Headscale
      headscaleApiUrl = settings.headscale_api_url || ''
      headscaleUrl = settings.headscale_url || ''
      originalHeadscaleUrl = headscaleUrl
      headscaleHasKey = !!settings.headscale_api_key

      // AdGuard
      adguardUsername = settings.adguard_username || ''
      adguardPassword = settings.adguard_password ? '••••••••' : ''
      adguardDashboardEnabled = settings.adguard_dashboard_enabled !== false
      adguardDashboardURL = settings.adguard_dashboard_url || ''
      originalAdguard = { username: adguardUsername, password: adguardPassword, dashboardEnabled: adguardDashboardEnabled }

      // Traefik
      if (traefikConfig) {
        traefikForm = {
          rateLimitAverage: traefikConfig.rateLimitAverage || 100,
          rateLimitBurst: traefikConfig.rateLimitBurst || 200,
          strictRateAverage: traefikConfig.strictRateAverage || 10,
          strictRateBurst: traefikConfig.strictRateBurst || 20,
          ipAllowlist: [...(traefikConfig.ipAllowlist || [])],
          newIP: '',
          dashboardEnabled: traefikConfig.dashboardEnabled !== false
        }
        originalTraefik = {
          rateLimitAverage: traefikForm.rateLimitAverage,
          rateLimitBurst: traefikForm.rateLimitBurst,
          strictRateAverage: traefikForm.strictRateAverage,
          strictRateBurst: traefikForm.strictRateBurst,
          ipAllowlist: [...traefikForm.ipAllowlist],
          dashboardEnabled: traefikForm.dashboardEnabled
        }
      }

      // Session
      sessionTimeout = settings.session_timeout || '24'
      originalSession = { timeout: sessionTimeout }

      // Scanner
      scannerSettings = {
        portStart: settings.scanner_port_start || 1,
        portEnd: settings.scanner_port_end || 5000,
        concurrent: settings.scanner_concurrent || 100,
        pauseMs: settings.scanner_pause_ms || 10,
        timeoutMs: settings.scanner_timeout_ms || 500
      }
      originalScanner = { ...scannerSettings }

      // UI (from localStorage)
      itemsPerPage = localStorage.getItem('settings_items_per_page') || '25'
    } catch (e) {
      toast('Failed to load settings: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  $effect(() => {
    headscaleUrlChanged = headscaleUrl !== originalHeadscaleUrl
  })

  $effect(() => {
    const userChanged = adguardUsername !== originalAdguard.username
    const passChanged = adguardPassword !== originalAdguard.password && adguardPassword !== '••••••••'
    const dashboardChanged = adguardDashboardEnabled !== originalAdguard.dashboardEnabled
    adguardChanged = userChanged || passChanged || dashboardChanged
  })

  $effect(() => {
    sessionChanged = sessionTimeout !== originalSession.timeout
  })

  // Derived state for scanner change detection
  const scannerHasChanges = $derived.by(() => {
    if (!originalScanner) return false
    return (
      scannerSettings.portStart !== originalScanner.portStart ||
      scannerSettings.portEnd !== originalScanner.portEnd ||
      scannerSettings.concurrent !== originalScanner.concurrent ||
      scannerSettings.pauseMs !== originalScanner.pauseMs ||
      scannerSettings.timeoutMs !== originalScanner.timeoutMs
    )
  })

  // Derived state for traefik change detection
  const traefikHasChanges = $derived.by(() => {
    if (!originalTraefik) return false
    return (
      traefikForm.rateLimitAverage !== originalTraefik.rateLimitAverage ||
      traefikForm.rateLimitBurst !== originalTraefik.rateLimitBurst ||
      traefikForm.strictRateAverage !== originalTraefik.strictRateAverage ||
      traefikForm.strictRateBurst !== originalTraefik.strictRateBurst ||
      traefikForm.dashboardEnabled !== originalTraefik.dashboardEnabled ||
      JSON.stringify(traefikForm.ipAllowlist) !== JSON.stringify(originalTraefik.ipAllowlist)
    )
  })

  // Save Headscale public URL
  async function saveHeadscale() {
    savingHeadscale = true
    try {
      await apiPut('/api/settings', {
        headscale_url: headscaleUrl
      })
      originalHeadscaleUrl = headscaleUrl
      headscaleUrlChanged = false
      toast('Headscale URL saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingHeadscale = false
    }
  }

  // Regenerate Headscale API key (only if expires within 7 days)
  async function regenerateHeadscaleKey() {
    regeneratingKey = true
    try {
      await apiPost('/api/setup/generate-apikey', {})
      headscaleHasKey = true
      toast('API key regenerated successfully', 'success')
    } catch (e) {
      toast(e.message || 'Failed to regenerate API key', 'error')
    } finally {
      regeneratingKey = false
    }
  }

  // Save AdGuard settings
  async function saveAdguard() {
    savingAdguard = true
    try {
      const res = await apiPut('/api/settings', {
        adguard_username: adguardUsername,
        adguard_password: adguardPassword === '••••••••' ? null : adguardPassword,
        adguard_dashboard_enabled: adguardDashboardEnabled
      })
      originalAdguard = { username: adguardUsername, password: adguardPassword, dashboardEnabled: adguardDashboardEnabled }
      adguardChanged = false

      // If AdGuard config was updated, restart the container
      if (res.adguardRestartRequired) {
        toast('Settings saved. Restarting AdGuard...', 'info')
        try {
          await apiPost('/api/docker/containers/adguard/restart')
          toast('AdGuard restarted successfully', 'success')
        } catch (e) {
          toast('Settings saved but failed to restart AdGuard: ' + e.message, 'warning')
        }
      } else {
        toast('AdGuard settings saved', 'success')
      }
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingAdguard = false
    }
  }

  // Save Session settings
  async function saveSession() {
    savingSession = true
    try {
      await apiPut('/api/settings', {
        session_timeout: sessionTimeout
      })
      originalSession = { timeout: sessionTimeout }
      sessionChanged = false
      toast('Session settings saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingSession = false
    }
  }

  // Save Scanner settings
  async function saveScanner() {
    savingScanner = true
    try {
      await apiPut('/api/settings', {
        scanner_port_start: parseInt(scannerSettings.portStart),
        scanner_port_end: parseInt(scannerSettings.portEnd),
        scanner_concurrent: parseInt(scannerSettings.concurrent),
        scanner_pause_ms: parseInt(scannerSettings.pauseMs),
        scanner_timeout_ms: parseInt(scannerSettings.timeoutMs)
      })
      originalScanner = { ...scannerSettings }
      toast('Scanner settings saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingScanner = false
    }
  }

  // Save Traefik settings
  async function saveTraefik() {
    savingTraefik = true
    try {
      const res = await apiPut('/api/traefik/config', {
        rateLimitAverage: traefikForm.rateLimitAverage,
        rateLimitBurst: traefikForm.rateLimitBurst,
        strictRateAverage: traefikForm.strictRateAverage,
        strictRateBurst: traefikForm.strictRateBurst,
        ipAllowlist: traefikForm.ipAllowlist,
        dashboardEnabled: traefikForm.dashboardEnabled
      })
      originalTraefik = {
        rateLimitAverage: traefikForm.rateLimitAverage,
        rateLimitBurst: traefikForm.rateLimitBurst,
        strictRateAverage: traefikForm.strictRateAverage,
        strictRateBurst: traefikForm.strictRateBurst,
        ipAllowlist: [...traefikForm.ipAllowlist],
        dashboardEnabled: traefikForm.dashboardEnabled
      }
      if (res.restartRequired) {
        toast('Configuration saved. Restarting Traefik...', 'info')
        try {
          await apiPost('/api/docker/containers/traefik/restart')
          toast('Traefik restarted successfully', 'success')
        } catch (e) {
          toast('Config saved but failed to restart Traefik: ' + e.message, 'warning')
        }
      } else {
        toast('Traefik settings saved', 'success')
      }
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingTraefik = false
    }
  }

  function addTraefikIP() {
    const ip = traefikForm.newIP.trim()
    if (ip && !traefikForm.ipAllowlist.includes(ip)) {
      traefikForm.ipAllowlist = [...traefikForm.ipAllowlist, ip]
      traefikForm.newIP = ''
    }
  }

  function removeTraefikIP(ip) {
    traefikForm.ipAllowlist = traefikForm.ipAllowlist.filter(i => i !== ip)
  }

  // Save UI settings (localStorage only)
  function saveUISettings() {
    localStorage.setItem('settings_items_per_page', itemsPerPage)
    toast('UI settings saved', 'success')
  }

  function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark')
  }

  // Geolocation settings functions
  async function loadGeoSettings() {
    loadingGeo = true
    try {
      const [settings, status] = await Promise.all([
        apiGet('/api/geo/settings'),
        apiGet('/api/geo/status')
      ])
      geoSettings = {
        lookup_provider: settings.lookup_provider || 'none',
        blocking_enabled: settings.blocking_enabled || false,
        auto_update: settings.auto_update || false,
        update_hour: settings.update_hour ?? 3,
        update_services: settings.update_services || 'all',
        maxmind_license_key: settings.maxmind_configured ? '••••••••' : '',
        ip2location_token: settings.ip2location_configured ? '••••••••' : '',
        ip2location_variant: settings.ip2location_variant || 'DB1'
      }
      originalGeoSettings = { ...geoSettings }
      geoStatus = status
      geoProviders = settings.providers || null
    } catch {
      // Ignore errors
    } finally {
      loadingGeo = false
    }
  }

  async function saveGeoSettings() {
    savingGeo = true
    try {
      // Don't send placeholder values for tokens/keys
      const payload = {
        ...geoSettings,
        maxmind_license_key: geoSettings.maxmind_license_key === '••••••••' ? undefined : geoSettings.maxmind_license_key,
        ip2location_token: geoSettings.ip2location_token === '••••••••' ? undefined : geoSettings.ip2location_token
      }
      await apiPut('/api/geo/settings', payload)
      originalGeoSettings = { ...geoSettings }
      // Reload status to see updated provider info
      geoStatus = await apiGet('/api/geo/status')
      toast('Geolocation settings saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingGeo = false
    }
  }

  async function triggerGeoUpdate() {
    triggeringGeoUpdate = true
    try {
      const res = await apiPost('/api/geo/update')
      if (res.errors > 0) {
        toast(`Update completed with ${res.errors} errors`, 'warning')
      } else {
        toast('Geolocation data updated successfully', 'success')
      }
      // Reload status
      geoStatus = await apiGet('/api/geo/status')
    } catch (e) {
      toast('Failed to update: ' + e.message, 'error')
    } finally {
      triggeringGeoUpdate = false
    }
  }

  // Check if geo settings have changed
  const geoHasChanges = $derived.by(() => {
    if (!originalGeoSettings) return false
    return JSON.stringify(geoSettings) !== JSON.stringify(originalGeoSettings)
  })

  // VPN Router functions
  async function loadRouterStatus() {
    try {
      routerStatus = await apiGet('/api/vpn/router/status')
    } catch (e) {
      routerStatus = { status: 'not_started', message: 'Failed to fetch status' }
    }
  }

  async function setupRouter() {
    routerLoading = true
    try {
      await apiPost('/api/vpn/router/setup')
      toast('VPN Router setup started', 'success')
      await loadRouterStatus()
    } catch (e) {
      toast('Failed to setup router: ' + e.message, 'error')
    } finally {
      routerLoading = false
    }
  }

  async function restartRouter() {
    routerLoading = true
    try {
      await apiPost('/api/vpn/router/restart')
      toast('VPN Router restarted', 'success')
      await loadRouterStatus()
    } catch (e) {
      toast('Failed to restart router: ' + e.message, 'error')
    } finally {
      routerLoading = false
    }
  }

  async function removeRouter() {
    routerLoading = true
    try {
      await apiDelete('/api/vpn/router')
      toast('VPN Router removed', 'success')
      await loadRouterStatus()
    } catch (e) {
      toast('Failed to remove router: ' + e.message, 'error')
    } finally {
      routerLoading = false
    }
  }

  // Set VPN-only mode
  async function setVPNOnlyMode(mode) {
    vpnOnlyLoading = true
    try {
      await apiPost('/api/traefik/vpn-only', { mode })
      vpnOnlyMode = mode
      const messages = {
        'off': 'VPN-only mode disabled',
        '403': 'VPN-only mode enabled (403 Forbidden)',
        'silent': 'VPN-only mode enabled (Silent Drop)'
      }
      toast(messages[mode], 'success')
    } catch (e) {
      toast('Failed to set VPN-only mode: ' + e.message, 'error')
    } finally {
      vpnOnlyLoading = false
    }
  }

  // Generate random secure credentials for AdGuard
  function regenerateAdguardCredentials() {
    const creds = generateAdguardCredentials()
    adguardUsername = creds.username
    adguardPassword = creds.password
    toast('Credentials generated', 'success')
  }

  onMount(() => {
    loadSettings()
    loadRouterStatus()
    loadGeoSettings()
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="settings"
    title="Settings"
    description="Configure your VPN admin panel. Manage Headscale connection, AdGuard integration, session preferences, and interface customization."
  />

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <!-- Two column grid -->
    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Headscale Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="server" size={16} />
            Headscale
          </h3>
        </div>
        <div class="kt-panel-body">
          <div class="grid grid-cols-2 gap-3">
            <Input
              id="headscaleApiUrl"
              label="Internal API URL"
              helperText="Auto-detected from Docker"
              type="url"
              value={headscaleApiUrl}
              prefixIcon="link"
              class="text-xs bg-muted/50"
              disabled
            />
            <Input
              id="headscaleUrl"
              label="Public URL"
              helperText="External URL for Tailscale clients"
              type="url"
              bind:value={headscaleUrl}
              placeholder="http://your-server-ip:8080"
              prefixIcon="link"
              class="text-xs"
            />
          </div>
          <div>
            <span class="block text-xs font-medium text-foreground mb-1">API Key</span>
            <div class="kt-input">
                {#if headscaleHasKey}
                  <Icon name="check" size={14} class="text-success" />
                  <span class="text-muted-foreground">Configured</span>
                {:else}
                  <Icon name="alert-circle" size={14} class="text-destructive" />
                  <span class="text-destructive">Not configured</span>
                {/if}
                <input
                  id=""
                  type=""
                  placeholder=""
                  class="kt-input w-full text-xs"
                  disabled
                />
                <Button
                  onclick={regenerateHeadscaleKey}
                  loading={regeneratingKey}
                  variant="ghost"
                  size="xs"
                  iconOnly
                  icon="refresh"
                  class="-me-1.5 size-6"
                  title="Regenerate API key"
                />
              </div>
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveHeadscale}
            loading={savingHeadscale}
            disabled={!headscaleUrlChanged}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
        </div>
      </div>

      <!-- AdGuard Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="shield" size={16} />
            AdGuard Home
          </h3>
          <Button
            onclick={regenerateAdguardCredentials}
            variant="outline"
            size="xs"
            icon="wand"
            title="Generate random secure credentials"
          >
            Generate
          </Button>
        </div>
        <div class="kt-panel-body">
          <div class="grid grid-cols-2 gap-3">
            <Input
              id="adguardUsername"
              label="Username"
              type="text"
              bind:value={adguardUsername}
              placeholder="admin"
              prefixIcon="user"
              class="text-xs"
            />
            <Input
              id="adguardPassword"
              label="Password"
              type="password"
              bind:value={adguardPassword}
              placeholder="Password"
              prefixIcon="lock"
              class="text-xs"
            />
          </div>
          <div class="flex items-center justify-between pt-3 border-t border-border">
            <div>
              <span class="text-xs font-medium text-foreground">Dashboard Access</span>
              <p class="text-[10px] text-muted-foreground">Allow external access to AdGuard web UI</p>
            </div>
            <Checkbox variant="switch" bind:checked={adguardDashboardEnabled} />
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveAdguard}
            loading={savingAdguard}
            disabled={!adguardChanged}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
          {#if adguardDashboardURL}
            <a href={adguardDashboardURL} target="_blank" class="kt-btn kt-btn-secondary kt-btn-sm">
              <Icon name="link" size={14} />
              Open Dashboard
            </a>
          {/if}
        </div>
      </div>

      <!-- Session Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="clock" size={16} />
            Session
          </h3>
        </div>
        <div class="kt-panel-body">
          <Select
            label="Session Timeout"
            bind:value={sessionTimeout}
            options={[
              { value: '1', label: '1 hour' },
              { value: '8', label: '8 hours' },
              { value: '24', label: '24 hours' },
              { value: '168', label: '7 days' },
              { value: '720', label: '30 days' }
            ]}
            helperText="How long until you need to login again"
          />
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveSession}
            loading={savingSession}
            disabled={!sessionChanged}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
        </div>
      </div>

      <!-- UI Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="layout" size={16} />
            Interface
          </h3>
        </div>
        <div class="kt-panel-body">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-xs font-medium text-foreground">Theme</div>
              <div class="text-[10px] text-muted-foreground">Current: {$theme}</div>
            </div>
            <Button
              onclick={toggleTheme}
              variant="secondary"
              size="sm"
              icon={$theme === 'dark' ? 'sun' : 'moon'}
            >
              {$theme === 'dark' ? 'Light' : 'Dark'}
            </Button>
          </div>
          <div class="flex items-end gap-2 border-t border-border pt-3">
            <Select
              label="Items per page"
              bind:value={itemsPerPage}
              options={[
                { value: '10', label: '10' },
                { value: '25', label: '25' },
                { value: '50', label: '50' },
                { value: '100', label: '100' }
              ]}
              class="flex-1"
            />
            <Button
              onclick={saveUISettings}
              variant="secondary"
              size="sm"
              icon="device-floppy"
              iconOnly
            />
          </div>
        </div>
      </div>

      <!-- Port Scanner Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="scan" size={16} />
            Port Scanner
          </h3>
        </div>
        <div class="kt-panel-body">
          <p class="text-[10px] text-muted-foreground">
            Default settings for scanning VPN client ports in Domain Routes.
          </p>
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Input
              label="Port Start"
              type="number"
              bind:value={scannerSettings.portStart}
              min="1"
              max="65535"
              prefixIcon="player-play"
              class="text-xs"
            />
            <Input
              label="Port End"
              type="number"
              bind:value={scannerSettings.portEnd}
              min="1"
              max="65535"
              prefixIcon="player-stop"
              class="text-xs"
            />
            <Input
              label="Concurrent"
              type="number"
              bind:value={scannerSettings.concurrent}
              min="10"
              max="500"
              prefixIcon="layers-subtract"
              class="text-xs"
            />
            <Input
              label="Pause (ms)"
              type="number"
              bind:value={scannerSettings.pauseMs}
              min="0"
              max="1000"
              prefixIcon="player-pause"
              class="text-xs"
            />
            <Input
              label="Timeout (ms)"
              type="number"
              bind:value={scannerSettings.timeoutMs}
              min="100"
              max="5000"
              prefixIcon="clock"
              class="text-xs"
            />
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveScanner}
            loading={savingScanner}
            disabled={!scannerHasChanges}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
        </div>
      </div>

      <!-- Cross-Network Router -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="route" size={16} />
            Cross-Network Router
          </h3>
          {#if routerStatus?.status === 'running'}
            <Badge variant="success" size="sm">Running</Badge>
          {:else if routerStatus?.status === 'starting'}
            <Badge variant="warning" size="sm">Starting</Badge>
          {:else}
            <Badge variant="muted" size="sm">Disabled</Badge>
          {/if}
        </div>
        <div class="kt-panel-body">
          {#if routerStatus?.status === 'running'}
            <div class="grid grid-cols-2 gap-2">
              <ContentBlock variant="data" label="Router IP" value={routerStatus.ip || '—'} mono padding="sm" />
              <ContentBlock variant="data" label="Route" value={routerStatus.advertisedRoute || '—'} mono padding="sm" />
            </div>
            <p class="text-[10px] text-muted-foreground">
              Routing between WireGuard and Headscale networks.
            </p>
          {:else if routerStatus?.status === 'starting'}
            <div class="flex items-center gap-2 p-2 bg-warning/10 rounded">
              <div class="w-4 h-4 border-2 border-warning/30 border-t-warning rounded-full animate-spin"></div>
              <div class="text-xs text-foreground">Starting up...</div>
            </div>
          {:else}
            <p class="text-[10px] text-muted-foreground">
              Enable routing between WireGuard and Headscale networks via a Tailscale container.
            </p>
          {/if}
        </div>
        <div class="kt-panel-footer">
          {#if routerStatus?.status === 'running'}
            <Button onclick={restartRouter} size="sm" variant="secondary" icon="refresh" disabled={routerLoading}>
              {routerLoading ? '...' : 'Restart'}
            </Button>
            <Button onclick={removeRouter} size="sm" variant="destructive" icon="trash" disabled={routerLoading}>
              {routerLoading ? '...' : 'Remove'}
            </Button>
          {:else if routerStatus?.status === 'starting'}
            <Button onclick={loadRouterStatus} size="sm" variant="secondary" icon="refresh">
              Check Status
            </Button>
          {:else}
            <Button onclick={setupRouter} size="sm" icon="play" disabled={routerLoading}>
              {routerLoading ? 'Setting up...' : 'Enable'}
            </Button>
          {/if}
        </div>
      </div>
    </div>

    <!-- Traefik Settings - Full width -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="route" size={16} />
          Traefik
        </h3>
      </div>
      <div class="kt-panel-body">
        <!-- Two columns: Rate Limiting + Switches -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <!-- Rate Limiting (4 inputs in 2x2) -->
          <div>
            <ContentBlock variant="header" title="Rate Limiting" />
            <div class="grid grid-cols-2 gap-3">
              <Input
                label="Standard (req/s)"
                type="number"
                bind:value={traefikForm.rateLimitAverage}
                prefixIcon="gauge"
                class="text-xs"
                min="1"
              />
              <Input
                label="Standard Burst"
                type="number"
                bind:value={traefikForm.rateLimitBurst}
                prefixIcon="bolt"
                class="text-xs"
                min="1"
              />
              <Input
                label="Strict (req/s)"
                type="number"
                bind:value={traefikForm.strictRateAverage}
                prefixIcon="gauge"
                class="text-xs"
                min="1"
              />
              <Input
                label="Strict Burst"
                type="number"
                bind:value={traefikForm.strictRateBurst}
                prefixIcon="bolt"
                class="text-xs"
                min="1"
              />
            </div>
          </div>

          <!-- Switches -->
          <div class="space-y-3">
            <ContentBlock variant="header" title="Access Control" />
            <ContentBlock title="Dashboard" description="Port 8080 (restart required)">
              <Checkbox variant="switch" bind:checked={traefikForm.dashboardEnabled} />
            </ContentBlock>
            <ContentBlock title="VPN-Only Mode" description="Restrict access to VPN clients">
              <div class="flex items-center gap-2">
                {#if vpnOnlyLoading}
                  <span class="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
                {/if}
                <Select
                  value={vpnOnlyMode}
                  options={[
                    { value: 'off', label: 'Disabled' },
                    { value: '403', label: '403 Forbidden' },
                    { value: 'silent', label: 'Silent Drop' }
                  ]}
                  onchange={(e) => setVPNOnlyMode(e.target.value)}
                  disabled={vpnOnlyLoading}
                />
              </div>
            </ContentBlock>
          </div>
        </div>

        <!-- IP Allowlist - Full width -->
        <div class="border-t border-border pt-3">
          <h4 class="text-xs font-medium text-foreground mb-2">IP Allowlist (VPN-only middleware)</h4>
          <Input
            type="text"
            bind:value={traefikForm.newIP}
            prefixIcon="network"
            placeholder="e.g., 192.168.1.0/24"
            class="text-xs"
            suffixAddonBtn={{ icon: "plus", label: "Add", onclick: addTraefikIP }}
            onkeydown={(e) => e.key === 'Enter' && addTraefikIP()}
          />
          {#if traefikForm.ipAllowlist.length > 0}
            <div class="flex flex-wrap gap-1.5 pt-2">
              {#each traefikForm.ipAllowlist as ip}
                <div class="flex items-center gap-1 px-2 py-0.5 bg-muted rounded text-xs">
                  <code>{ip}</code>
                  <button onclick={() => removeTraefikIP(ip)} class="p-0.5 hover:text-destructive">
                    <Icon name="x" size={10} class="cursor-pointer"/>
                  </button>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-[10px] text-muted-foreground italic pt-2">No IP ranges configured</p>
          {/if}
        </div>
      </div>
      <div class="kt-panel-footer justify-end">
        <Button
          onclick={saveTraefik}
          loading={savingTraefik}
          disabled={!traefikHasChanges}
          size="sm"
          icon="device-floppy"
        >
          Save
        </Button>
      </div>
    </div>

    <!-- Geolocation Settings - Full width -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="world" size={16} />
          Geolocation
        </h3>
      </div>
      {#if loadingGeo}
        <div class="kt-panel-body flex items-center justify-center py-8">
          <div class="w-5 h-5 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
        </div>
      {:else}
        <div class="kt-panel-body">
          <!-- Two columns: IP Lookup + Toggles -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <!-- IP Lookup Provider -->
            <div>
              <ContentBlock variant="header" title="IP Lookup Provider" />
              <Select
                label="Provider"
                bind:value={geoSettings.lookup_provider}
                options={[
                  { value: 'none', label: 'None (disabled)' },
                  { value: 'maxmind', label: 'MaxMind GeoLite2' },
                  { value: 'ip2location', label: 'IP2Location Lite' }
                ]}
              />
              {#if geoSettings.lookup_provider === 'maxmind'}
                <div class="mt-3">
                  <Input
                    label="License Key"
                    type="password"
                    bind:value={geoSettings.maxmind_license_key}
                    placeholder="Your MaxMind license key"
                    prefixIcon="key"
                    helperText="Free at maxmind.com/en/geolite2/signup"
                  />
                </div>
              {:else if geoSettings.lookup_provider === 'ip2location'}
                <div class="space-y-3 mt-3">
                  <Select
                    label="Database Variant"
                    bind:value={geoSettings.ip2location_variant}
                    options={geoProviders?.ip2location?.variants?.map(v => ({ value: v.id, label: `${v.name}` })) || [{ value: 'DB1', label: 'DB1 - Country' }]}
                  />
                  <Input
                    label="Download Token"
                    type="password"
                    bind:value={geoSettings.ip2location_token}
                    placeholder="Your IP2Location download token"
                    prefixIcon="key"
                    helperText="Required. Get at ip2location.com/register"
                  />
                </div>
              {/if}
              {#if geoStatus?.providers && geoSettings.lookup_provider !== 'none'}
                <div class="mt-3 p-2 bg-muted/50 rounded text-[10px]">
                  {#if geoStatus.providers[geoSettings.lookup_provider]?.available}
                    <div class="flex items-center gap-1 text-success">
                      <Icon name="check" size={12} />
                      <span>Database available ({(geoStatus.providers[geoSettings.lookup_provider].file_size / 1024 / 1024).toFixed(1)}MB)</span>
                    </div>
                    {#if geoStatus.providers[geoSettings.lookup_provider].last_update}
                      <div class="text-muted-foreground mt-1">Last updated: {geoStatus.providers[geoSettings.lookup_provider].last_update}</div>
                    {/if}
                  {:else}
                    <div class="flex items-center gap-1 text-warning">
                      <Icon name="alert-circle" size={12} />
                      <span>Database not downloaded yet. Save settings and click "Update Now".</span>
                    </div>
                  {/if}
                </div>
              {/if}
            </div>

            <!-- Toggles -->
            <div class="space-y-3">
              <ContentBlock variant="header" title="Options" />
              <ContentBlock title="Country Blocking" description="Block traffic using IPDeny zone files">
                <Checkbox variant="switch" bind:checked={geoSettings.blocking_enabled} />
              </ContentBlock>
              {#if !geoSettings.blocking_enabled}
                <div class="p-2 bg-info/10 border border-info/20 rounded text-[10px] text-muted-foreground">
                  <Icon name="info-circle" size={12} class="inline mr-1" />
                  Firewall country controls hidden when disabled.
                </div>
              {/if}
              <ContentBlock title="Auto-Update" description="Update databases daily">
                <Checkbox variant="switch" bind:checked={geoSettings.auto_update} />
              </ContentBlock>
              {#if geoSettings.auto_update}
                <div class="grid grid-cols-2 gap-3">
                  <Select
                    label="Update Time"
                    bind:value={geoSettings.update_hour}
                    options={Array.from({length: 24}, (_, i) => ({ value: i, label: `${i.toString().padStart(2, '0')}:00` }))}
                  />
                  <Select
                    label="Services"
                    bind:value={geoSettings.update_services}
                    options={[
                      { value: 'all', label: 'All services' },
                      { value: 'lookup', label: 'IP lookup only' },
                      { value: 'blocking', label: 'Country blocking only' }
                    ]}
                  />
                </div>
              {/if}
            </div>
          </div>

          {#if geoStatus?.last_update_lookup || geoStatus?.last_update_blocking}
            <div class="text-[10px] text-muted-foreground pt-3 border-t border-border">
              {#if geoStatus.last_update_lookup}
                <span>Lookup: {geoStatus.last_update_lookup}</span>
              {/if}
              {#if geoStatus.last_update_lookup && geoStatus.last_update_blocking}
                <span class="mx-2">·</span>
              {/if}
              {#if geoStatus.last_update_blocking}
                <span>Blocking: {geoStatus.last_update_blocking}</span>
              {/if}
            </div>
          {/if}
        </div>
        <div class="kt-panel-footer justify-between">
          <Button
            onclick={triggerGeoUpdate}
            loading={triggeringGeoUpdate}
            disabled={geoSettings.lookup_provider === 'none' && !geoSettings.blocking_enabled}
            variant="secondary"
            size="sm"
            icon="refresh"
            title={geoSettings.lookup_provider === 'none' && !geoSettings.blocking_enabled ? 'Select a provider or enable blocking first' : 'Update geolocation databases now'}
          >
            Update Now
          </Button>
          <Button
            onclick={saveGeoSettings}
            loading={savingGeo}
            disabled={!geoHasChanges}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
        </div>
      {/if}
    </div>

    <!-- About - Full width -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="info-circle" size={16} />
          About
        </h3>
      </div>
      <div class="kt-panel-body flex items-center justify-between !py-3">
        <div class="text-xs text-muted-foreground">
          <p class="font-medium text-foreground">VPN Admin Panel</p>
          <p class="mt-0.5">Headscale + WireGuard management interface</p>
        </div>
        <div class="text-[10px] text-muted-foreground text-right">
          <p>Built with Svelte 5</p>
          <p>Tailwind CSS v4 + KTUI</p>
          <div class="flex items-center justify-end gap-3 mt-2">
            <a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer" class="text-muted-foreground hover:text-foreground transition-colors" data-kt-tooltip>
              <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
              <span data-kt-tooltip-content class="kt-tooltip hidden">MaxMind GeoLite2</span>
            </a>
            <a href="https://www.ip2location.com" target="_blank" rel="noopener noreferrer" class="text-muted-foreground hover:text-foreground transition-colors" data-kt-tooltip>
              <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>
              <span data-kt-tooltip-content class="kt-tooltip hidden">IP2Location Lite</span>
            </a>
            <a href="https://www.ipdeny.com" target="_blank" rel="noopener noreferrer" class="text-muted-foreground hover:text-foreground transition-colors" data-kt-tooltip>
              <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="8" y1="8" x2="16" y2="16"/><line x1="16" y1="8" x2="8" y2="16"/></svg>
              <span data-kt-tooltip-content class="kt-tooltip hidden">IPDeny Zone Files</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>
