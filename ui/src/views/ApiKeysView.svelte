<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiDelete } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'

  let { loading = $bindable(true) } = $props()

  let apiKeys = $state([])
  let showCreateModal = $state(false)
  let showDeleteModal = $state(false)
  let deletingKey = $state(null)
  let deleting = $state(false)
  let newExpiration = $state('90')
  let newKey = $state(null)
  let creating = $state(false)
  let searchQuery = $state('')

  async function loadKeys() {
    try {
      const res = await apiGet('/api/hs/apikeys')
      const keys = res.apiKeys || []
      apiKeys = keys.map(k => ({ ...k, _expired: isExpired(k.expiration) }))
    } catch (e) {
      toast('Failed to load API keys: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  function parseDate(dateVal) {
    if (!dateVal) return null
    if (dateVal.seconds) return new Date(dateVal.seconds * 1000)
    if (typeof dateVal === 'string') {
      const truncated = dateVal.replace(/\.(\d{3})\d+/, '.$1')
      return new Date(truncated)
    }
    return new Date(dateVal)
  }

  function formatDate(dateVal) {
    const date = parseDate(dateVal)
    if (!date) return 'Never'
    return date.toLocaleDateString()
  }

  function formatRelativeDate(exp) {
    const date = parseDate(exp)
    if (!date) return 'Never'
    const now = new Date()
    const diffMs = date - now
    const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24))

    if (diffDays < 0) {
      const absDays = Math.abs(diffDays)
      if (absDays === 1) return 'Expired yesterday'
      if (absDays < 7) return `Expired ${absDays} days ago`
      if (absDays < 30) return `Expired ${Math.floor(absDays / 7)} weeks ago`
      return `Expired ${Math.floor(absDays / 30)} months ago`
    }
    if (diffDays === 0) return 'Expires today'
    if (diffDays === 1) return 'Expires tomorrow'
    if (diffDays < 7) return `Expires in ${diffDays} days`
    if (diffDays < 30) return `Expires in ${Math.floor(diffDays / 7)} weeks`
    if (diffDays < 365) return `Expires in ${Math.floor(diffDays / 30)} months`
    return `Expires in ${Math.floor(diffDays / 365)} years`
  }

  function isExpired(exp) {
    const date = parseDate(exp)
    if (!date) return false
    const now = new Date()
    const expMinute = new Date(date.getFullYear(), date.getMonth(), date.getDate(), date.getHours(), date.getMinutes())
    const nowMinute = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), now.getMinutes())
    return expMinute <= nowMinute
  }

  function getDaysUntilExpiry(exp) {
    const date = parseDate(exp)
    if (!date) return null
    const now = new Date()
    return Math.ceil((date - now) / (1000 * 60 * 60 * 24))
  }

  // Filtered and sorted keys - active first, then by expiration date
  const filteredKeys = $derived(
    apiKeys
      .filter(k => k.prefix.toLowerCase().includes(searchQuery.toLowerCase()))
      .sort((a, b) => {
        // Active keys first
        if (a._expired !== b._expired) return a._expired ? 1 : -1
        // Then by expiration date (soonest first for active, most recent for expired)
        const dateA = parseDate(a.expiration)
        const dateB = parseDate(b.expiration)
        if (!dateA || !dateB) return 0
        return a._expired ? dateB - dateA : dateA - dateB
      })
  )

  async function createKey() {
    creating = true
    try {
      const expiration = new Date()
      expiration.setDate(expiration.getDate() + parseInt(newExpiration))

      const res = await apiPost('/api/hs/apikeys', { expiration: expiration.toISOString() })
      newKey = res.apiKey
      toast('API key created', 'success')
      loadKeys()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  function confirmExpireKey(key) {
    deletingKey = key
    showDeleteModal = true
  }

  async function expireKey() {
    if (!deletingKey) return
    deleting = true
    try {
      await apiDelete(`/api/hs/apikeys/${deletingKey.prefix}`)
      toast('Key expired', 'success')
      showDeleteModal = false
      deletingKey = null
      loadKeys()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      deleting = false
    }
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => toast('Copied!', 'success')).catch(() => fallbackCopy(text))
    } else {
      fallbackCopy(text)
    }
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea')
    textarea.value = text
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.appendChild(textarea)
    textarea.select()
    try {
      document.execCommand('copy')
      toast('Copied!', 'success')
    } catch (e) {
      toast('Failed to copy', 'error')
    }
    document.body.removeChild(textarea)
  }

  onMount(loadKeys)
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="key" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">API Keys</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Generate API keys for programmatic access to Headscale. Use these keys for automation,
          scripts, or third-party integrations. Keys can be set to expire for enhanced security.
        </p>
      </div>
    </div>
  </div>

  <!-- Toolbar -->
  <Toolbar bind:search={searchQuery} placeholder="Search keys...">
    <Button onclick={() => { showCreateModal = true; newKey = null }} size="sm">
      <Icon name="plus" size={16} />
      Create Key
    </Button>
  </Toolbar>

  {#if loading}
    <div class="flex justify-center py-12">
      <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    </div>
  {:else if filteredKeys.length > 0}
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {#each filteredKeys as key (key.id + '-' + (key.expiration?.seconds || key.expiration))}
        {@const daysLeft = getDaysUntilExpiry(key.expiration)}
        {@const isExpiringSoon = daysLeft !== null && daysLeft > 0 && daysLeft <= 7}
        {@const borderColor = key._expired ? 'border-l-red-500' : isExpiringSoon ? 'border-l-amber-500' : 'border-l-emerald-500'}

        <div class="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors shadow-sm border-l-2 {borderColor}">
          <!-- Header -->
          <div class="flex items-center gap-3 p-3">
            <div class="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 {key._expired ? 'bg-red-500/10 text-red-500' : isExpiringSoon ? 'bg-amber-500/10 text-amber-500' : 'bg-emerald-500/10 text-emerald-500'}">
              <Icon name="key" size={18} />
            </div>
            <div class="flex-1 min-w-0">
              <code class="text-sm font-mono text-foreground truncate block">{key.prefix}...</code>
              <div class="text-[11px] text-muted-foreground flex items-center gap-1 mt-0.5">
                <Icon name="clock" size={11} />
                {formatRelativeDate(key.expiration)}
              </div>
            </div>
          </div>

          <!-- Info -->
          <div class="grid grid-cols-2 gap-x-3 border-t border-border px-3 py-2.5 text-[11px]">
            <div class="flex items-center gap-1.5">
              <Icon name="plus" size={12} class="text-slate-400 dark:text-zinc-600" />
              <span class="text-slate-600 dark:text-zinc-400">{formatDate(key.createdAt)}</span>
            </div>
            <div class="flex items-center gap-1.5">
              <Icon name="clock" size={12} class="text-slate-400 dark:text-zinc-600" />
              <span class="text-slate-600 dark:text-zinc-400">{formatDate(key.expiration)}</span>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-between px-2 py-1.5 border-t border-border bg-muted/30">
            <div class="flex items-center gap-1 text-[10px]">
              <span class="h-1.5 w-1.5 rounded-full {key._expired ? 'bg-red-500' : isExpiringSoon ? 'bg-amber-500' : 'bg-emerald-500'}"></span>
              <span class="{key._expired ? 'text-red-600 dark:text-red-400' : isExpiringSoon ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'} font-medium">
                {key._expired ? 'Expired' : isExpiringSoon ? 'Expiring soon' : 'Active'}
              </span>
            </div>
            {#if !key._expired}
              <button
                onclick={() => confirmExpireKey(key)}
                class="p-1.5 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors cursor-pointer"
                title="Expire key"
              >
                <Icon name="ban" size={14} />
              </button>
            {/if}
          </div>
        </div>
      {/each}

      <!-- Add key card -->
      <article
        onclick={() => { showCreateModal = true; newKey = null }}
        class="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-slate-300 bg-slate-50 p-4 text-center text-xs text-slate-500 transition hover:border-slate-400 hover:bg-slate-100 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:bg-zinc-800/70"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200/80 text-slate-600 dark:bg-zinc-700 dark:text-zinc-100">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-slate-700 dark:text-zinc-100">Create API key</div>
        <p class="max-w-[200px] text-slate-400 dark:text-zinc-500">
          Generate keys for programmatic access
        </p>
      </article>
    </div>
  {:else if apiKeys.length > 0}
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
      <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No API keys</h4>
      <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Create an API key for programmatic access</p>
      <Button onclick={() => { showCreateModal = true; newKey = null }} size="sm" class="mt-4">
        <Icon name="plus" size={14} />
        Create Key
      </Button>
    </div>
  {/if}
</div>

<!-- Create Modal -->
<Modal bind:open={showCreateModal} title="Create API Key" size="sm">
  {#if newKey}
    <div class="space-y-4">
      <div class="flex items-center gap-3 pb-3 border-b border-border">
        <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-success/15 text-success">
          <Icon name="check" size={20} />
        </div>
        <div>
          <p class="font-medium text-foreground">Key Created</p>
          <p class="text-xs text-muted-foreground">Save this key now</p>
        </div>
      </div>

      <div class="kt-alert kt-alert-warning">
        <Icon name="alert-triangle" size={16} />
        <div>
          <p class="text-sm">You won't be able to see this key again.</p>
          <code class="block text-xs font-mono break-all mt-2 p-2 bg-muted rounded">{newKey}</code>
        </div>
      </div>
    </div>
  {:else}
    <div>
      <label class="kt-label">Expiration</label>
      <select bind:value={newExpiration} class="kt-input w-full">
        <option value="7">7 days</option>
        <option value="30">30 days</option>
        <option value="90">90 days</option>
        <option value="365">1 year</option>
      </select>
      <p class="text-xs text-muted-foreground mt-1.5">Key will expire on {new Date(Date.now() + parseInt(newExpiration) * 24 * 60 * 60 * 1000).toLocaleDateString()}</p>
    </div>
  {/if}

  {#snippet footer()}
    {#if newKey}
      <Button onclick={() => copyToClipboard(newKey)} icon="copy">Copy to Clipboard</Button>
      <Button onclick={() => showCreateModal = false} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
      <Button onclick={createKey} disabled={creating}>
        {creating ? 'Creating...' : 'Create'}
      </Button>
    {/if}
  {/snippet}
</Modal>

<!-- Expire Confirmation Modal -->
<Modal bind:open={showDeleteModal} title="Expire API Key" size="sm">
  {#if deletingKey}
    <div class="kt-alert kt-alert-destructive">
      <Icon name="alert-triangle" size={18} />
      <div>
        <p class="font-medium">Expire key {deletingKey.prefix}...?</p>
        <p class="text-sm opacity-80 mt-0.5">This key will no longer work for API access. This action cannot be undone.</p>
      </div>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => { showDeleteModal = false; deletingKey = null }} variant="secondary" disabled={deleting}>Cancel</Button>
    <Button onclick={expireKey} variant="destructive" icon="ban" disabled={deleting}>
      {deleting ? 'Expiring...' : 'Expire Key'}
    </Button>
  {/snippet}
</Modal>
