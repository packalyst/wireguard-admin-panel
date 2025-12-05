<script>
  import { onMount } from 'svelte'
  import { theme, apiGet, apiPost } from './stores/app.js'
  import Dashboard from './views/Dashboard.svelte'
  import Login from './views/Login.svelte'
  import SetupWizard from './views/SetupWizard.svelte'

  let user = $state(null)
  let checking = $state(true)
  let needsSetup = $state(false)
  let showAdguardBanner = $state(false)

  onMount(async () => {
    // First check if setup is complete
    try {
      const setupStatus = await apiGet('/api/setup/status')
      if (!setupStatus.completed) {
        needsSetup = true
        checking = false
        return
      }
      // Check if AdGuard password needs to be configured
      showAdguardBanner = !setupStatus.adguardPassChanged
    } catch (e) {
      console.error('Setup check failed:', e)
    }

    // Setup is complete, check for existing session
    const token = localStorage.getItem('session_token')
    if (token) {
      try {
        const data = await apiGet('/api/auth/validate')
        user = data.user
      } catch (e) {
        // Invalid session, clear it
        localStorage.removeItem('session_token')
        localStorage.removeItem('session_expires')
      }
    }
    checking = false
  })

  function handleSetupComplete(loggedInUser) {
    needsSetup = false
    user = loggedInUser
    // After setup, AdGuard is not configured yet
    showAdguardBanner = true
  }

  function handleLogin(loggedInUser) {
    user = loggedInUser
  }

  function handleLogout() {
    apiPost('/api/auth/logout').catch(() => {})
    localStorage.removeItem('session_token')
    localStorage.removeItem('session_expires')
    user = null
  }
</script>

{#if checking}
  <div class="flex items-center justify-center h-full">
    <div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
  </div>
{:else if needsSetup}
  <SetupWizard onComplete={handleSetupComplete} />
{:else if user}
  <Dashboard onLogout={handleLogout} {showAdguardBanner} onDismissAdguardBanner={() => showAdguardBanner = false} />
{:else}
  <Login onLogin={handleLogin} />
{/if}
