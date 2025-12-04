<script>
  import { onMount } from 'svelte'
  import { theme, toast, apiGet, apiPost, apiPut } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'

  let { loading = $bindable(true) } = $props()
  let savingAdguard = $state(false)
  let savingSession = $state(false)
  let savingTraefik = $state(false)
  let regeneratingKey = $state(false)

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

  // UI settings (stored in localStorage)
  let itemsPerPage = $state('25')

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
  function generateAdguardCredentials() {
    // Generate random username (8 characters, alphanumeric)
    const usernameChars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    let username = 'admin_'
    for (let i = 0; i < 8; i++) {
      username += usernameChars.charAt(Math.floor(Math.random() * usernameChars.length))
    }

    // Generate secure random password (16 characters with special chars)
    const passwordChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    let password = ''
    for (let i = 0; i < 16; i++) {
      password += passwordChars.charAt(Math.floor(Math.random() * passwordChars.length))
    }

    adguardUsername = username
    adguardPassword = password

    toast('Credentials generated', 'success')
  }

  onMount(loadSettings)
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="settings" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Settings</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Configure your VPN admin panel. Manage Headscale connection, AdGuard integration,
          session preferences, and interface customization.
        </p>
      </div>
    </div>
  </div>

  {#if loading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    </div>
  {:else}
    <!-- Two column grid -->
    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Headscale Settings -->
      <div class="bg-card border border-border rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-border bg-muted/30">
          <div class="flex items-center gap-2">
            <Icon name="server" size={16} class="text-primary" />
            <h3 class="text-sm font-semibold text-foreground">Headscale</h3>
          </div>
        </div>
        <div class="p-4 space-y-3">
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
            <label class="block text-xs font-medium text-foreground mb-1">API Key</label>
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
                  disabled={regeneratingKey}
                  variant="ghost"
                  size="xs"
                  iconOnly
                  icon={regeneratingKey ? undefined : "refresh"}
                  class="-me-1.5 size-6"
                  title="Regenerate API key"
                >
                  {#if regeneratingKey}
                    <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
                  {/if}
                </Button>
              </div>
          </div>
          <div class="pt-2">
            <Button
              onclick={saveHeadscale}
              disabled={savingHeadscale || !headscaleUrlChanged}
              size="sm"
              icon={savingHeadscale ? undefined : "device-floppy"}
            >
              {#if savingHeadscale}
                <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
              {:else}
                Save
              {/if}
            </Button>
          </div>
        </div>
      </div>

      <!-- AdGuard Settings -->
      <div class="bg-card border border-border rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-border bg-muted/30">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <Icon name="shield" size={16} class="text-primary" />
              <h3 class="text-sm font-semibold text-foreground">AdGuard Home</h3>
            </div>
            <Button
              onclick={generateAdguardCredentials}
              variant="ghost"
              size="xs"
              icon="wand"
              title="Generate random secure credentials"
            >
              Generate
            </Button>
          </div>
        </div>
        <div class="p-4 space-y-3">
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
            <input type="checkbox" class="kt-switch" bind:checked={adguardDashboardEnabled} />
          </div>
          <div class="flex items-center gap-2 pt-2">
            <Button
              onclick={saveAdguard}
              disabled={savingAdguard || !adguardChanged}
              size="sm"
              icon={savingAdguard ? undefined : "device-floppy"}
            >
              {#if savingAdguard}
                <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
              {:else}
                Save
              {/if}
            </Button>
            {#if adguardDashboardURL}
              <a href={adguardDashboardURL} target="_blank" class="kt-btn kt-btn-secondary kt-btn-sm">
                <Icon name="link" size={14} />
                Open Dashboard
              </a>
            {/if}
          </div>
        </div>
      </div>

      <!-- Session Settings -->
      <div class="bg-card border border-border rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-border bg-muted/30">
          <div class="flex items-center gap-2">
            <Icon name="clock" size={16} class="text-primary" />
            <h3 class="text-sm font-semibold text-foreground">Session</h3>
          </div>
        </div>
        <div class="p-4 space-y-3">
          <div>
            <label for="sessionTimeout" class="block text-xs font-medium text-foreground mb-1">Session Timeout</label>
            <select id="sessionTimeout" bind:value={sessionTimeout} class="kt-input w-full text-xs">
              <option value="1">1 hour</option>
              <option value="8">8 hours</option>
              <option value="24">24 hours</option>
              <option value="168">7 days</option>
              <option value="720">30 days</option>
            </select>
            <p class="text-[10px] text-muted-foreground mt-1">How long until you need to login again</p>
          </div>
          <div class="pt-2">
            <Button
              onclick={saveSession}
              disabled={savingSession || !sessionChanged}
              size="sm"
              icon={savingSession ? undefined : "device-floppy"}
            >
              {#if savingSession}
                <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
              {:else}
                Save
              {/if}
            </Button>
          </div>
        </div>
      </div>

      <!-- UI Settings -->
      <div class="bg-card border border-border rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-border bg-muted/30">
          <div class="flex items-center gap-2">
            <Icon name="layout" size={16} class="text-primary" />
            <h3 class="text-sm font-semibold text-foreground">Interface</h3>
          </div>
        </div>
        <div class="p-4 space-y-3">
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
          <div class="border-t border-border pt-3">
            <label for="itemsPerPage" class="block text-xs font-medium text-foreground mb-1">Items per page</label>
            <div class="flex items-center gap-2">
              <select id="itemsPerPage" bind:value={itemsPerPage} class="kt-input flex-1 text-xs">
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
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
      </div>
    </div>

    <!-- Traefik Settings - Full width -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <div class="px-4 py-3 border-b border-border bg-muted/30">
        <div class="flex items-center gap-2">
          <Icon name="route" size={16} class="text-primary" />
          <h3 class="text-sm font-semibold text-foreground">Traefik</h3>
        </div>
      </div>
      <div class="p-4 space-y-4">
        <!-- Rate Limiting -->
        <div>
          <h4 class="text-xs font-medium text-foreground mb-2">Rate Limiting</h4>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Input
              label="Standard (req/s)"
              labelClass="block text-[10px] text-muted-foreground mb-1"
              type="number"
              bind:value={traefikForm.rateLimitAverage}
              class="w-full text-xs"
              min="1"
            />
            <Input
              label="Standard Burst"
              labelClass="block text-[10px] text-muted-foreground mb-1"
              type="number"
              bind:value={traefikForm.rateLimitBurst}
              class="w-full text-xs"
              min="1"
            />
            <Input
              label="Strict (req/s)"
              labelClass="block text-[10px] text-muted-foreground mb-1"
              type="number"
              bind:value={traefikForm.strictRateAverage}
              class="w-full text-xs"
              min="1"
            />
            <Input
              label="Strict Burst"
              labelClass="block text-[10px] text-muted-foreground mb-1"
              type="number"
              bind:value={traefikForm.strictRateBurst}
              class="w-full text-xs"
              min="1"
            />
          </div>
        </div>

        <!-- Dashboard Toggle -->
        <div class="flex items-center justify-between py-2 border-t border-border">
          <div>
            <div class="text-xs font-medium text-foreground">Dashboard</div>
            <div class="text-[10px] text-muted-foreground">Enable Traefik dashboard on port 8080 (requires restart)</div>
          </div>
          <input type="checkbox" class="kt-switch" bind:checked={traefikForm.dashboardEnabled} />
        </div>

        <!-- VPN-Only Mode Dropdown -->
        <div class="flex items-center justify-between py-2 border-t border-border">
          <div>
            <div class="text-xs font-medium text-foreground">VPN-Only Mode</div>
            <div class="text-[10px] text-muted-foreground">Restrict admin UI access to VPN clients only</div>
          </div>
          <div class="flex items-center gap-2">
            {#if vpnOnlyLoading}
              <span class="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
            {/if}
            <select
              class="kt-input text-xs py-1 px-2"
              value={vpnOnlyMode}
              onchange={(e) => setVPNOnlyMode(e.target.value)}
              disabled={vpnOnlyLoading}
            >
              <option value="off">Disabled</option>
              <option value="403">403 Forbidden</option>
              <option value="silent">Silent Drop</option>
            </select>
          </div>
        </div>

        <!-- IP Allowlist -->
        <div class="border-t border-border pt-3">
          <h4 class="text-xs font-medium text-foreground mb-2">IP Allowlist (VPN-only middleware)</h4>
          <div class="flex gap-2 mb-2">
            <Input
              type="text"
              bind:value={traefikForm.newIP}
              prefixIcon="network"
              placeholder="e.g., 192.168.1.0/24"
              class="flex-1 text-xs"
              onkeydown={(e) => e.key === 'Enter' && addTraefikIP()}
            >
              {#snippet suffixButton()}
                <Button
                  onclick={addTraefikIP}
                  variant="ghost"
                  size="xs"
                  iconOnly
                  icon="plus"
                  class="-me-1.5 size-6"
                />
              {/snippet}
            </Input>
          </div>
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
            <p class="text-[10px] text-muted-foreground italic">No IP ranges configured</p>
          {/if}
        </div>

        <!-- Save Button -->
        <div class="flex justify-end pt-2 border-t border-border">
          <Button
            onclick={saveTraefik}
            disabled={savingTraefik || !traefikHasChanges}
            size="sm"
            icon={savingTraefik ? undefined : "device-floppy"}
          >
            {#if savingTraefik}
              <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
            {:else}
              Save
            {/if}
          </Button>
        </div>
      </div>
    </div>

    <!-- About - Full width -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <div class="px-4 py-3 border-b border-border bg-muted/30">
        <div class="flex items-center gap-2">
          <Icon name="info-circle" size={16} class="text-primary" />
          <h3 class="text-sm font-semibold text-foreground">About</h3>
        </div>
      </div>
      <div class="p-4 flex items-center justify-between">
        <div class="text-xs text-muted-foreground">
          <p class="font-medium text-foreground">VPN Admin Panel</p>
          <p class="mt-0.5">Headscale + WireGuard management interface</p>
        </div>
        <div class="text-[10px] text-muted-foreground text-right">
          <p>Built with Svelte 5</p>
          <p>Tailwind CSS v4 + KTUI</p>
        </div>
      </div>
    </div>
  {/if}
</div>
