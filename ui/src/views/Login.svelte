<script>
  import { theme, toast, apiPost } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'

  let { onLogin } = $props()

  let username = $state('')
  let password = $state('')
  let loading = $state(false)
  let error = $state('')

  function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark')
  }

  async function handleLogin() {
    error = ''
    loading = true

    try {
      const data = await apiPost('/api/auth/login', { username, password })

      // Store session token
      localStorage.setItem('session_token', data.token)
      localStorage.setItem('session_expires', data.expiresAt)

      toast('Login successful', 'success')

      // Notify parent component
      if (onLogin) onLogin(data.user)
    } catch (e) {
      error = e.message || 'Login failed'
    } finally {
      loading = false
    }
  }
</script>

<div class="min-h-screen flex flex-col lg:flex-row">
  <!-- Mobile Header - Only visible on mobile -->
  <div class="lg:hidden bg-gradient-to-br from-[#0f1419] via-[#1a1f37] to-[#1a1f37] text-white px-6 pt-12 pb-16 text-center relative overflow-hidden">
    <!-- Decorative gradient -->
    <div class="absolute top-0 right-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl"></div>
    <div class="absolute bottom-0 left-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl"></div>

    <div class="relative z-10">
      <div class="flex items-center justify-center gap-3 mb-6">
        <div class="w-12 h-12 bg-primary rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
          <Icon name="shield" size={24} class="text-white" />
        </div>
      </div>
      <h1 class="text-2xl font-bold mb-2">Welcome Back</h1>
      <p class="text-sm text-gray-400">Sign in to your VPN Admin Panel</p>
    </div>
  </div>

  <!-- Left Panel - Desktop only -->
  <div class="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-[#0f1419] via-[#1a1f37] to-[#1a1f37] text-white p-16 flex-col justify-center relative overflow-hidden">
    <!-- Decorative gradient orbs -->
    <div class="absolute top-0 right-0 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl"></div>
    <div class="absolute bottom-0 left-0 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl"></div>

    <div class="relative z-10 max-w-2xl mx-auto w-full">
      <!-- Header -->
      <div class="mb-12">
        <div class="flex items-center gap-3 mb-8">
          <div class="w-11 h-11 bg-primary rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
            <Icon name="shield" size={22} class="text-white" />
          </div>
          <span class="text-lg font-semibold tracking-tight">WireGuard Admin</span>
        </div>

        <h2 class="text-4xl font-bold mb-3 leading-tight">
          Enterprise VPN<br/>Management Platform
        </h2>
        <p class="text-gray-400 text-base leading-relaxed">
          Secure, scalable infrastructure for modern organizations
        </p>
      </div>

      <!-- Features Grid - 2 columns -->
      <div class="grid grid-cols-2 gap-4 mb-10">
        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="server" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Multi-Server</h3>
          </div>
          <p class="text-xs text-gray-400 leading-relaxed">Deploy across multiple regions</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="shield-check" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Enterprise Security</h3>
          </div>
          <p class="text-xs text-gray-400 leading-relaxed">Military-grade encryption</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="activity" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Live Monitoring</h3>
          </div>
          <p class="text-xs text-gray-400 leading-relaxed">Real-time analytics dashboard</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="users" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">User Management</h3>
          </div>
          <p class="text-xs text-gray-400 leading-relaxed">Centralized access control</p>
        </div>
      </div>

      <!-- Footer -->
      <div class="flex flex-wrap gap-6 text-xs text-gray-400">
        <div class="flex items-center gap-2">
          <div class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
          <span>99.9% Uptime</span>
        </div>
        <div class="flex items-center gap-2">
          <div class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
          <span>SOC 2 Certified</span>
        </div>
        <div class="flex items-center gap-2">
          <div class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
          <span>GDPR Compliant</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Right Panel / Form Section -->
  <div class="flex-1 bg-card flex items-center justify-center p-6 lg:p-8 relative -mt-8 lg:mt-0 rounded-t-3xl lg:rounded-none">
    <!-- Theme toggle -->
    <button
      onclick={toggleTheme}
      class="absolute top-4 right-4 lg:top-6 lg:right-6 w-9 h-9 rounded-lg flex items-center justify-center hover:bg-muted transition-colors"
    >
      {#if $theme === 'dark'}
        <Icon name="sun" size={18} />
      {:else}
        <Icon name="moon" size={18} />
      {/if}
    </button>

    <div class="w-full max-w-md">
      <!-- Header - Hidden on mobile since we have header above -->
      <div class="hidden lg:block mb-8">
        <h1 class="text-2xl font-semibold mb-2">Welcome Back</h1>
        <p class="text-sm text-muted-foreground">Sign in to manage your VPN infrastructure</p>
      </div>

      {#if error}
        <div class="flex items-center gap-2 px-3 py-2.5 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive mb-4 lg:mb-6">
          <Icon name="alert-circle" size={16} />
          <span>{error}</span>
        </div>
      {/if}

      <form onsubmit={(e) => { e.preventDefault(); handleLogin() }} class="space-y-3.5 lg:space-y-4">
        <!-- Username Field -->
        <Input
          id="username"
          label="Username"
          labelClass="block text-xs lg:text-sm font-medium mb-1 lg:mb-1.5"
          type="text"
          bind:value={username}
          placeholder="Enter your username"
          autocomplete="username"
          prefixIcon="user"
          class="w-full"
          required
        />

        <!-- Password Field -->
        <Input
          id="password"
          label="Password"
          labelClass="block text-xs lg:text-sm font-medium mb-1 lg:mb-1.5"
          type="password"
          bind:value={password}
          placeholder="Enter your password"
          autocomplete="current-password"
          prefixIcon="lock"
          class="w-full"
          required
        />

        <!-- Remember me & Forgot password -->
        <div class="flex items-center justify-between text-xs lg:text-sm pt-0.5 lg:pt-1">
          <label class="flex items-center gap-1.5 lg:gap-2 cursor-pointer">
            <input type="checkbox" class="w-3.5 lg:w-4 h-3.5 lg:h-4 rounded" />
            <span>Remember me</span>
          </label>
          <a href="#" class="text-primary hover:underline">Forgot password?</a>
        </div>

        <!-- Submit Button -->
        <Button
          type="submit"
          disabled={loading}
          class="w-full justify-center mt-4 lg:mt-6"
        >
          {#if loading}
            <span class="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin mr-2"></span>
            <span>Signing in...</span>
          {:else}
            <span>Sign In</span>
          {/if}
        </Button>
      </form>

      <!-- Divider -->
      <div class="relative my-6 lg:my-8">
        <div class="absolute inset-0 flex items-center">
          <div class="w-full border-t border-border"></div>
        </div>
       
      </div>
    </div>
  </div>
</div>
