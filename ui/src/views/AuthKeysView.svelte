<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost } from '../stores/app.js'
  import { copyWithToast } from '../stores/helpers.js'
  import { parseDate, formatDateShort, formatExpiryDate, isExpired, getDaysUntilExpiry } from '$lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  let { loading = $bindable(true) } = $props()

  let users = $state([])
  let authKeys = $state([])
  let showCreateModal = $state(false)
  let showExpireModal = $state(false)
  let expiringKey = $state(null)
  let expiring = $state(false)
  let createForm = $state({ user: '', reusable: false, ephemeral: false, expiration: '90' })
  let creating = $state(false)
  let searchQuery = $state('')
  let pollInterval = null

  // Get server URL for command display (from settings)
  let serverUrl = $state('')

  async function loadData() {
    try {
      const [usersRes, settings] = await Promise.all([
        apiGet('/api/hs/users'),
        apiGet('/api/settings')
      ])
      users = usersRes.users || []
      serverUrl = settings.headscale_url || ''

      // Load keys for all users
      const allKeys = []
      for (const user of users) {
        try {
          const res = await apiGet(`/api/hs/preauthkeys?user=${user.name}`)
          const keys = res.preAuthKeys || []
          keys.forEach(k => {
            k.userName = user.name
            k._expired = isExpired(k.expiration)
            allKeys.push(k)
          })
        } catch (e) {
          // Skip users with no keys or errors
        }
      }
      authKeys = allKeys
    } catch (e) {
      toast('Failed to load auth keys: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // Filtered and sorted keys - active first, then by expiration
  const filteredKeys = $derived(
    authKeys
      .filter(k =>
        k.key?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        k.userName?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        k.user?.toLowerCase().includes(searchQuery.toLowerCase())
      )
      .sort((a, b) => {
        // Active (not expired, not used) first
        const aActive = !a._expired && !a.used
        const bActive = !b._expired && !b.used
        if (aActive !== bActive) return aActive ? -1 : 1
        // Then by expiration date
        const dateA = parseDate(a.expiration)
        const dateB = parseDate(b.expiration)
        if (!dateA || !dateB) return 0
        return aActive ? dateA - dateB : dateB - dateA
      })
  )

  async function createKey() {
    if (!createForm.user) {
      toast('Please select a user', 'error')
      return
    }
    creating = true
    try {
      const expiration = new Date()
      const days = parseInt(createForm.expiration)
      expiration.setDate(expiration.getDate() + days)

      await apiPost('/api/hs/preauthkeys', {
        user: createForm.user,
        reusable: createForm.reusable,
        ephemeral: createForm.ephemeral,
        expiration: expiration.toISOString()
      })
      toast('Auth key created', 'success')
      showCreateModal = false
      createForm = { user: '', reusable: false, ephemeral: false, expiration: '90' }
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  function confirmExpireKey(key) {
    expiringKey = key
    showExpireModal = true
  }

  async function expireKey() {
    if (!expiringKey) return
    expiring = true
    try {
      await apiPost('/api/hs/preauthkeys/expire', { user: expiringKey.userName || expiringKey.user, key: expiringKey.key })
      toast('Key expired', 'success')
      showExpireModal = false
      expiringKey = null
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      expiring = false
    }
  }

  const copyToClipboard = (text) => copyWithToast(text, toast)

  onMount(() => {
    loadData()
    pollInterval = setInterval(loadData, 30000)
  })

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval)
  })
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="key" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Pre-Authentication Keys</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Generate keys to automatically register devices without manual approval. Perfect for CI/CD pipelines,
          containerized workloads, or bulk device onboarding. Copy the command from any key to connect instantly.
        </p>
      </div>
    </div>
  </div>

  <!-- Toolbar -->
  <Toolbar bind:search={searchQuery} placeholder="Search keys...">
    <Button onclick={() => showCreateModal = true} size="sm">
      <Icon name="plus" size={16} />
      Create Key
    </Button>
  </Toolbar>

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else if filteredKeys.length > 0}
    <div class="grid-cards">
      {#each filteredKeys as key (key.key)}
        {@const daysLeft = getDaysUntilExpiry(key.expiration)}
        {@const isExpiringSoon = daysLeft !== null && daysLeft > 0 && daysLeft <= 7}
        {@const isUsed = key.used}
        {@const isActive = !key._expired && !isUsed}
        {@const statusClass = key._expired ? 'error' : isUsed ? 'muted' : isExpiringSoon ? 'warning' : 'success'}

        <div class="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors shadow-sm card-border-{statusClass}">
          <!-- Header -->
          <div class="flex items-center gap-3 p-3">
            <div class="status-icon status-icon-{statusClass}">
              <Icon name="key" size={18} />
            </div>
            <div class="flex-1 min-w-0">
              <code class="text-xs font-mono text-foreground truncate block">{key.key?.substring(0, 12)}...</code>
              <div class="text-[11px] text-muted-foreground flex items-center gap-1 mt-0.5">
                <Icon name="user" size={11} />
                {key.userName || key.user}
              </div>
            </div>
          </div>

          <!-- Info -->
          <div class="border-t border-border px-3 py-2.5 text-[11px] space-y-1.5">
            <div class="flex items-center gap-1.5">
              <Icon name="clock" size={12} class="text-slate-400 dark:text-zinc-600" />
              <span class="text-slate-600 dark:text-zinc-400 truncate">{formatExpiryDate(key.expiration)}</span>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              {#if key.reusable}
                <span class="flex items-center gap-1 text-info">
                  <Icon name="refresh" size={12} />
                  Reusable
                </span>
              {:else}
                <span class="flex items-center gap-1 text-slate-500 dark:text-zinc-500">
                  <Icon name="hand-stop" size={12} />
                  Single-use
                </span>
              {/if}
              {#if key.ephemeral}
                <span class="flex items-center gap-1 text-warning">
                  <Icon name="clock" size={12} />
                  Ephemeral
                </span>
              {/if}
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-between px-2 py-1.5 border-t border-border bg-muted/30">
            <div class="flex items-center gap-1 text-[10px]">
              <span class="status-dot status-dot-{statusClass}"></span>
              <span class="{statusClass === 'muted' ? 'text-muted-foreground' : `status-text-${statusClass}`} font-medium">
                {key._expired ? 'Expired' : isUsed ? 'Used' : isExpiringSoon ? 'Expiring soon' : 'Active'}
              </span>
            </div>
            <div class="flex items-center gap-0.5">
              <button
                onclick={() => copyToClipboard(`tailscale up --login-server=${serverUrl} --authkey=${key.key}`)}
                class="icon-btn"
                title="Copy command"
              >
                <Icon name="copy" size={14} />
              </button>
              {#if isActive}
                <button
                  onclick={() => confirmExpireKey(key)}
                  class="icon-btn-destructive"
                  title="Expire key"
                >
                  <Icon name="ban" size={14} />
                </button>
              {/if}
            </div>
          </div>
        </div>
      {/each}

      <!-- Add key card -->
      <article
        onclick={() => showCreateModal = true}
        class="add-item-card"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200/80 text-slate-600 dark:bg-zinc-700 dark:text-zinc-100">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-slate-700 dark:text-zinc-100">Create auth key</div>
        <p class="max-w-[200px] text-slate-400 dark:text-zinc-500">
          Allow devices to join automatically
        </p>
      </article>
    </div>
  {:else if authKeys.length > 0}
    <!-- No search results -->
    <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
      <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
        <Icon name="search" size={20} />
      </div>
      <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No keys found</h4>
      <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Try a different search term</p>
    </div>
  {:else}
    <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
      <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
        <Icon name="key" size={20} />
      </div>
      <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No auth keys</h4>
      <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Create keys to allow devices to join automatically</p>
      <Button onclick={() => showCreateModal = true} size="sm" class="mt-4">
        <Icon name="plus" size={14} />
        Create Key
      </Button>
    </div>
  {/if}
</div>

<!-- Create Modal -->
<Modal bind:open={showCreateModal} title="Create Auth Key" size="sm">
  <div class="space-y-4">
    <Select label="User" bind:value={createForm.user}>
      <option value="">Select user...</option>
      {#each users as user}
        <option value={user.name}>{user.name}</option>
      {/each}
    </Select>
    <Select
      label="Expiration"
      bind:value={createForm.expiration}
      options={[
        { value: '1', label: '1 day' },
        { value: '7', label: '7 days' },
        { value: '30', label: '30 days' },
        { value: '90', label: '90 days' },
        { value: '365', label: '1 year' }
      ]}
      helperText="Key will expire on {new Date(Date.now() + parseInt(createForm.expiration) * 24 * 60 * 60 * 1000).toLocaleDateString()}"
    />
    <div class="flex gap-6">
      <label class="flex items-center gap-2 cursor-pointer">
        <input type="checkbox" bind:checked={createForm.reusable} class="w-4 h-4 rounded border-border" />
        <span class="text-sm text-foreground">Reusable</span>
      </label>
      <label class="flex items-center gap-2 cursor-pointer">
        <input type="checkbox" bind:checked={createForm.ephemeral} class="w-4 h-4 rounded border-border" />
        <span class="text-sm text-foreground">Ephemeral</span>
      </label>
    </div>
    <div class="text-xs text-muted-foreground bg-muted/50 p-2 rounded space-y-1">
      <p><strong>Reusable:</strong> Key can register multiple devices (e.g., CI runners)</p>
      <p><strong>Ephemeral:</strong> Nodes auto-removed when offline (e.g., containers)</p>
      <p class="text-[10px] opacity-75">Both can be enabled for short-lived workloads like CI/CD pipelines</p>
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
    <Button onclick={createKey} disabled={creating || !createForm.user}>
      {creating ? 'Creating...' : 'Create'}
    </Button>
  {/snippet}
</Modal>

<!-- Expire Confirmation Modal -->
<Modal bind:open={showExpireModal} title="Expire Auth Key" size="sm">
  {#if expiringKey}
    <div class="space-y-4">
      <div class="kt-alert kt-alert-destructive">
        <Icon name="alert-triangle" size={18} />
        <div>
          <p class="font-medium">Expire this key?</p>
          <p class="text-sm opacity-80 mt-0.5">This key will no longer work to register new devices. This action cannot be undone.</p>
        </div>
      </div>

      <div class="text-xs text-muted-foreground">
        <p><strong>Key:</strong> <code class="font-mono">{expiringKey.key?.substring(0, 16)}...</code></p>
        <p><strong>User:</strong> {expiringKey.userName || expiringKey.user}</p>
      </div>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => { showExpireModal = false; expiringKey = null }} variant="secondary" disabled={expiring}>Cancel</Button>
    <Button onclick={expireKey} variant="destructive" icon="ban" disabled={expiring}>
      {expiring ? 'Expiring...' : 'Expire Key'}
    </Button>
  {/snippet}
</Modal>
