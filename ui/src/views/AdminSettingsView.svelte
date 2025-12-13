<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'

  let { loading = $bindable(true) } = $props()

  // Tab state
  let activeTab = $state('profile')

  // Profile state
  let profile = $state({
    username: '',
    email: '',
    avatarUrl: '',
    totpEnabled: false,
    createdAt: '',
    lastLogin: ''
  })
  let emailChanged = $state(false)
  let originalEmail = ''
  let savingProfile = $state(false)

  // Password change state
  let passwordForm = $state({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  })
  let changingPassword = $state(false)

  // 2FA state
  let totpSetup = $state(null) // { secret, qrCodeUrl }
  let totpCode = $state('')
  let settingUp2FA = $state(false)
  let verifying2FA = $state(false)
  let disabling2FA = $state(false)
  let disablePassword = $state('')
  let showDisable2FAModal = $state(false)

  // SMTP state
  let smtpConfig = $state({
    mode: 'builtin',
    host: '',
    port: 587,
    username: '',
    password: false,
    from: '',
    tls: 'starttls'
  })
  let smtpPassword = $state('')
  let smtpChanged = $state(false)
  let originalSmtp = $state(null)
  let savingSmtp = $state(false)
  let testingSmtp = $state(false)
  let testEmail = $state('')

  async function loadProfile() {
    try {
      const data = await apiGet('/api/auth/profile')
      profile = {
        username: data.username || '',
        email: data.email || '',
        avatarUrl: data.avatarUrl || '',
        totpEnabled: data.totpEnabled || false,
        createdAt: data.createdAt || '',
        lastLogin: data.lastLogin || ''
      }
      originalEmail = profile.email
    } catch (e) {
      toast('Failed to load profile: ' + e.message, 'error')
    }
  }

  async function loadSmtp() {
    try {
      const data = await apiGet('/api/smtp')
      smtpConfig = {
        mode: data.mode || 'builtin',
        host: data.host || '',
        port: data.port || 587,
        username: data.username || '',
        password: data.password || false,
        from: data.from || '',
        tls: data.tls || 'starttls'
      }
      originalSmtp = { ...smtpConfig }
    } catch (e) {
      toast('Failed to load SMTP settings: ' + e.message, 'error')
    }
  }

  async function loadAll() {
    loading = true
    await Promise.all([loadProfile(), loadSmtp()])
    loading = false
  }

  $effect(() => {
    emailChanged = profile.email !== originalEmail
  })

  $effect(() => {
    if (!originalSmtp) return
    smtpChanged = (
      smtpConfig.mode !== originalSmtp.mode ||
      smtpConfig.host !== originalSmtp.host ||
      smtpConfig.port !== originalSmtp.port ||
      smtpConfig.username !== originalSmtp.username ||
      smtpConfig.from !== originalSmtp.from ||
      smtpConfig.tls !== originalSmtp.tls ||
      smtpPassword !== ''
    )
  })

  // Profile functions
  async function saveProfile() {
    savingProfile = true
    try {
      await apiPut('/api/auth/profile', { email: profile.email })
      originalEmail = profile.email
      // Reload to get new avatar URL
      await loadProfile()
      toast('Profile updated', 'success')
    } catch (e) {
      toast('Failed to update profile: ' + e.message, 'error')
    } finally {
      savingProfile = false
    }
  }

  // Password functions
  async function changePassword() {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast('Passwords do not match', 'error')
      return
    }
    if (passwordForm.newPassword.length < 8) {
      toast('Password must be at least 8 characters', 'error')
      return
    }

    changingPassword = true
    try {
      await apiPut('/api/auth/password', {
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword
      })
      passwordForm = { currentPassword: '', newPassword: '', confirmPassword: '' }
      toast('Password changed successfully', 'success')
    } catch (e) {
      toast(e.message || 'Failed to change password', 'error')
    } finally {
      changingPassword = false
    }
  }

  // 2FA functions
  async function setup2FA() {
    settingUp2FA = true
    try {
      const data = await apiPost('/api/auth/2fa/setup')
      totpSetup = data
    } catch (e) {
      toast('Failed to setup 2FA: ' + e.message, 'error')
    } finally {
      settingUp2FA = false
    }
  }

  async function verify2FA() {
    if (totpCode.length !== 6) {
      toast('Please enter a 6-digit code', 'error')
      return
    }

    verifying2FA = true
    try {
      await apiPost('/api/auth/2fa/verify', { code: totpCode })
      profile.totpEnabled = true
      totpSetup = null
      totpCode = ''
      toast('2FA enabled successfully', 'success')
    } catch (e) {
      toast(e.message || 'Invalid code', 'error')
    } finally {
      verifying2FA = false
    }
  }

  function cancelSetup() {
    totpSetup = null
    totpCode = ''
  }

  async function disable2FA() {
    if (!disablePassword) {
      toast('Please enter your password', 'error')
      return
    }

    disabling2FA = true
    try {
      await apiDelete('/api/auth/2fa', { password: disablePassword })
      profile.totpEnabled = false
      showDisable2FAModal = false
      disablePassword = ''
      toast('2FA disabled', 'success')
    } catch (e) {
      toast(e.message || 'Failed to disable 2FA', 'error')
    } finally {
      disabling2FA = false
    }
  }

  // SMTP functions
  async function saveSmtp() {
    savingSmtp = true
    try {
      await apiPut('/api/smtp', {
        mode: smtpConfig.mode,
        host: smtpConfig.host,
        port: smtpConfig.port,
        username: smtpConfig.username,
        password: smtpPassword || null,
        from: smtpConfig.from,
        tls: smtpConfig.tls
      })
      smtpPassword = ''
      originalSmtp = { ...smtpConfig }
      smtpChanged = false
      toast('SMTP settings saved', 'success')
    } catch (e) {
      toast('Failed to save SMTP settings: ' + e.message, 'error')
    } finally {
      savingSmtp = false
    }
  }

  async function testSmtp() {
    if (!testEmail || !testEmail.includes('@')) {
      toast('Please enter a valid email address', 'error')
      return
    }

    testingSmtp = true
    try {
      await apiPost('/api/smtp/test', { to: testEmail })
      toast('Test email sent to ' + testEmail, 'success')
    } catch (e) {
      toast('Failed to send test email: ' + e.message, 'error')
    } finally {
      testingSmtp = false
    }
  }

  onMount(loadAll)
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="user-cog" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Admin Settings</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Manage your account profile, security settings, and email configuration.
        </p>
      </div>
    </div>
  </div>

  {#if loading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    </div>
  {:else}
    <!-- Tabs -->
    <div class="flex gap-1 p-1 bg-muted/50 rounded-lg w-fit">
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md transition-colors {activeTab === 'profile' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}"
        onclick={() => activeTab = 'profile'}
      >
        <Icon name="user" size={14} class="inline mr-1" />
        Profile
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md transition-colors {activeTab === 'security' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}"
        onclick={() => activeTab = 'security'}
      >
        <Icon name="shield-lock" size={14} class="inline mr-1" />
        Security
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md transition-colors {activeTab === 'email' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}"
        onclick={() => activeTab = 'email'}
      >
        <Icon name="mail" size={14} class="inline mr-1" />
        Email
      </button>
    </div>

    <!-- Profile Tab -->
    {#if activeTab === 'profile'}
      <div class="bg-card border border-border rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-border bg-muted/30">
          <h3 class="text-sm font-semibold text-foreground">Profile</h3>
        </div>
        <div class="p-4">
          <div class="flex items-start gap-6">
            <!-- Avatar -->
            <div class="flex-shrink-0">
              <div class="w-20 h-20 rounded-full overflow-hidden bg-muted border-2 border-border">
                {#if profile.avatarUrl}
                  <img src={profile.avatarUrl} alt="Avatar" class="w-full h-full object-cover" />
                {:else}
                  <div class="w-full h-full flex items-center justify-center text-muted-foreground">
                    <Icon name="user" size={32} />
                  </div>
                {/if}
              </div>
              <p class="text-[10px] text-muted-foreground text-center mt-1">Gravatar</p>
            </div>

            <!-- Form -->
            <div class="flex-1 space-y-3">
              <Input
                label="Username"
                value={profile.username}
                prefixIcon="user"
                disabled
                class="text-xs bg-muted/50"
              />
              <Input
                label="Email"
                type="email"
                bind:value={profile.email}
                prefixIcon="mail"
                placeholder="your@email.com"
                helperText="Used for Gravatar avatar"
                class="text-xs"
              />
              <div class="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <span class="text-muted-foreground">Created:</span>
                  <span class="text-foreground ml-1">{profile.createdAt ? new Date(profile.createdAt).toLocaleDateString() : '-'}</span>
                </div>
                <div>
                  <span class="text-muted-foreground">Last login:</span>
                  <span class="text-foreground ml-1">{profile.lastLogin ? new Date(profile.lastLogin).toLocaleString() : '-'}</span>
                </div>
              </div>
              <div class="pt-2">
                <Button
                  onclick={saveProfile}
                  disabled={savingProfile || !emailChanged}
                  size="sm"
                  icon={savingProfile ? undefined : "device-floppy"}
                >
                  {#if savingProfile}
                    <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
                  {:else}
                    Save
                  {/if}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    {/if}

    <!-- Security Tab -->
    {#if activeTab === 'security'}
      <div class="grid gap-4 lg:grid-cols-2">
        <!-- Password Change -->
        <div class="bg-card border border-border rounded-lg overflow-hidden">
          <div class="px-4 py-3 border-b border-border bg-muted/30">
            <div class="flex items-center gap-2">
              <Icon name="key" size={16} class="text-primary" />
              <h3 class="text-sm font-semibold text-foreground">Change Password</h3>
            </div>
          </div>
          <div class="p-4 space-y-3">
            <Input
              label="Current Password"
              type="password"
              bind:value={passwordForm.currentPassword}
              prefixIcon="lock"
              class="text-xs"
            />
            <Input
              label="New Password"
              type="password"
              bind:value={passwordForm.newPassword}
              prefixIcon="lock"
              helperText="Min 8 chars, uppercase, lowercase, number, special"
              class="text-xs"
            />
            <Input
              label="Confirm Password"
              type="password"
              bind:value={passwordForm.confirmPassword}
              prefixIcon="lock"
              class="text-xs"
            />
            <div class="pt-2">
              <Button
                onclick={changePassword}
                disabled={changingPassword || !passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword}
                size="sm"
                icon={changingPassword ? undefined : "check"}
              >
                {#if changingPassword}
                  <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
                {:else}
                  Change Password
                {/if}
              </Button>
            </div>
          </div>
        </div>

        <!-- 2FA -->
        <div class="bg-card border border-border rounded-lg overflow-hidden">
          <div class="px-4 py-3 border-b border-border bg-muted/30">
            <div class="flex items-center gap-2">
              <Icon name="shield-check" size={16} class="text-primary" />
              <h3 class="text-sm font-semibold text-foreground">Two-Factor Authentication</h3>
            </div>
          </div>
          <div class="p-4">
            {#if profile.totpEnabled}
              <!-- 2FA Enabled -->
              <div class="flex items-center justify-between p-3 bg-success/10 border border-success/20 rounded-lg">
                <div class="flex items-center gap-2">
                  <Icon name="shield-check" size={20} class="text-success" />
                  <div>
                    <p class="text-sm font-medium text-foreground">2FA is enabled</p>
                    <p class="text-xs text-muted-foreground">Your account is protected</p>
                  </div>
                </div>
                <Button
                  onclick={() => showDisable2FAModal = true}
                  variant="destructive"
                  size="sm"
                >
                  Disable
                </Button>
              </div>
            {:else if totpSetup}
              <!-- Setup in progress -->
              <div class="space-y-4">
                <div class="text-center">
                  <p class="text-xs text-muted-foreground mb-3">Scan this QR code with your authenticator app</p>
                  <div class="inline-block p-2 bg-white rounded-lg">
                    <img src={totpSetup.qrCodeUrl} alt="QR Code" class="w-48 h-48" />
                  </div>
                </div>
                <div class="text-center">
                  <p class="text-xs text-muted-foreground mb-1">Or enter this code manually:</p>
                  <code class="text-xs bg-muted px-2 py-1 rounded font-mono">{totpSetup.secret}</code>
                </div>
                <Input
                  label="Verification Code"
                  type="text"
                  bind:value={totpCode}
                  placeholder="000000"
                  prefixIcon="key"
                  class="text-xs text-center tracking-widest"
                  maxlength="6"
                />
                <div class="flex gap-2">
                  <Button
                    onclick={verify2FA}
                    disabled={verifying2FA || totpCode.length !== 6}
                    size="sm"
                    class="flex-1"
                    icon={verifying2FA ? undefined : "check"}
                  >
                    {#if verifying2FA}
                      <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
                    {:else}
                      Verify & Enable
                    {/if}
                  </Button>
                  <Button onclick={cancelSetup} variant="secondary" size="sm">
                    Cancel
                  </Button>
                </div>
              </div>
            {:else}
              <!-- 2FA Not enabled -->
              <div class="text-center py-4">
                <Icon name="shield" size={32} class="text-muted-foreground mx-auto mb-2" />
                <p class="text-sm text-foreground mb-1">2FA is not enabled</p>
                <p class="text-xs text-muted-foreground mb-4">Add an extra layer of security to your account</p>
                <Button
                  onclick={setup2FA}
                  disabled={settingUp2FA}
                  size="sm"
                  icon={settingUp2FA ? undefined : "shield-plus"}
                >
                  {#if settingUp2FA}
                    <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
                  {:else}
                    Enable 2FA
                  {/if}
                </Button>
              </div>
            {/if}
          </div>
        </div>
      </div>
    {/if}

    <!-- Email Tab -->
    {#if activeTab === 'email'}
      <div class="bg-card border border-border rounded-lg overflow-hidden">
        <div class="px-4 py-3 border-b border-border bg-muted/30">
          <div class="flex items-center gap-2">
            <Icon name="mail-cog" size={16} class="text-primary" />
            <h3 class="text-sm font-semibold text-foreground">SMTP Configuration</h3>
          </div>
        </div>
        <div class="p-4 space-y-4">
          <!-- Mode Selection -->
          <div>
            <label class="block text-xs font-medium text-foreground mb-2">Email Mode</label>
            <div class="flex gap-3">
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="radio" bind:group={smtpConfig.mode} value="builtin" class="kt-radio" />
                <span class="text-xs">Built-in (Postfix)</span>
              </label>
              <label class="flex items-center gap-2 cursor-pointer">
                <input type="radio" bind:group={smtpConfig.mode} value="external" class="kt-radio" />
                <span class="text-xs">External SMTP</span>
              </label>
            </div>
            <p class="text-[10px] text-muted-foreground mt-1">
              {#if smtpConfig.mode === 'builtin'}
                Uses the built-in Postfix container for sending emails
              {:else}
                Configure an external SMTP server (Gmail, Mailgun, etc.)
              {/if}
            </p>
          </div>

          {#if smtpConfig.mode === 'external'}
            <div class="grid grid-cols-2 gap-3">
              <Input
                label="SMTP Host"
                bind:value={smtpConfig.host}
                placeholder="smtp.gmail.com"
                prefixIcon="server"
                class="text-xs"
              />
              <Input
                label="Port"
                type="number"
                bind:value={smtpConfig.port}
                placeholder="587"
                prefixIcon="hash"
                class="text-xs"
              />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <Input
                label="Username"
                bind:value={smtpConfig.username}
                placeholder="user@example.com"
                prefixIcon="user"
                class="text-xs"
              />
              <Input
                label="Password"
                type="password"
                bind:value={smtpPassword}
                placeholder={smtpConfig.password ? '********' : 'Password'}
                prefixIcon="lock"
                class="text-xs"
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-foreground mb-1">TLS Mode</label>
              <select bind:value={smtpConfig.tls} class="kt-input w-full text-xs">
                <option value="none">None</option>
                <option value="starttls">STARTTLS (port 587)</option>
                <option value="tls">Implicit TLS (port 465)</option>
              </select>
            </div>
          {/if}

          <Input
            label="From Address"
            bind:value={smtpConfig.from}
            placeholder="noreply@yourdomain.com"
            prefixIcon="mail"
            helperText="The sender address for outgoing emails"
            class="text-xs"
          />

          <div class="flex items-center gap-3 pt-2 border-t border-border">
            <Button
              onclick={saveSmtp}
              disabled={savingSmtp || !smtpChanged}
              size="sm"
              icon={savingSmtp ? undefined : "device-floppy"}
            >
              {#if savingSmtp}
                <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
              {:else}
                Save
              {/if}
            </Button>
          </div>

          <!-- Test Email -->
          <div class="pt-3 border-t border-border">
            <label class="block text-xs font-medium text-foreground mb-2">Send Test Email</label>
            <div class="flex gap-2">
              <Input
                type="email"
                bind:value={testEmail}
                placeholder="test@example.com"
                prefixIcon="mail"
                class="flex-1 text-xs"
              />
              <Button
                onclick={testSmtp}
                disabled={testingSmtp || !testEmail}
                variant="secondary"
                size="sm"
                icon={testingSmtp ? undefined : "send"}
              >
                {#if testingSmtp}
                  <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
                {:else}
                  Test
                {/if}
              </Button>
            </div>
          </div>
        </div>
      </div>
    {/if}
  {/if}
</div>

<!-- Disable 2FA Modal -->
<Modal bind:open={showDisable2FAModal} title="Disable 2FA" size="sm">
  <div class="space-y-4">
    <p class="text-sm text-muted-foreground">
      Enter your password to disable two-factor authentication.
    </p>
    <Input
      label="Password"
      type="password"
      bind:value={disablePassword}
      prefixIcon="lock"
      class="text-xs"
    />
  </div>

  {#snippet footer()}
    <div class="flex justify-end gap-2">
      <Button onclick={() => { showDisable2FAModal = false; disablePassword = '' }} variant="secondary" size="sm">
        Cancel
      </Button>
      <Button
        onclick={disable2FA}
        disabled={disabling2FA || !disablePassword}
        variant="destructive"
        size="sm"
      >
        {#if disabling2FA}
          <span class="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
        {:else}
          Disable 2FA
        {/if}
      </Button>
    </div>
  {/snippet}
</Modal>
