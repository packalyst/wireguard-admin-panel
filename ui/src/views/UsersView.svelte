<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'

  let { loading = $bindable(true) } = $props()

  let users = $state([])
  let nodes = $state([])
  let pollInterval = null

  async function loadData() {
    try {
      const [usersRes, nodesRes] = await Promise.all([
        apiGet('/api/hs/users'),
        apiGet('/api/hs/nodes')
      ])
      users = usersRes.users || []
      nodes = nodesRes.nodes || []
    } catch (e) {
      toast('Failed to load users: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  onMount(() => {
    loadData()
    pollInterval = setInterval(loadData, 30000)
  })

  onDestroy(() => {
    if (pollInterval) clearInterval(pollInterval)
  })

  // Modals
  let showCreateModal = $state(false)
  let showEditModal = $state(false)
  let showDeleteModal = $state(false)
  let editingUser = $state(null)
  let deletingUser = $state(null)

  // Form state
  let newUserName = $state('')
  let creating = $state(false)
  let deleting = $state(false)
  let selectedColor = $state('')
  let selectedAvatar = $state('')
  let searchQuery = $state('')
  let customizationVersion = $state(0) // Force reactivity on customization changes

  // Color and emoji options
  const colors = [
    '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
    '#ec4899', '#f43f5e', '#ef4444', '#f97316',
    '#eab308', '#84cc16', '#22c55e', '#14b8a6',
    '#06b6d4', '#3b82f6', '#64748b', '#1e293b'
  ]

  const emojis = ['😀', '😎', '🤖', '👨‍💻', '👩‍💻', '🦊', '🐱', '🐶', '🦁', '🐯', '🦄', '🐸', '🌟', '⚡', '🔥', '💎']

  // LocalStorage for user customizations
  function getUserCustomization(userName) {
    try {
      const data = localStorage.getItem(`user_custom_${userName}`)
      return data ? JSON.parse(data) : null
    } catch {
      return null
    }
  }

  function saveUserCustomization(userName, data) {
    localStorage.setItem(`user_custom_${userName}`, JSON.stringify(data))
  }

  function getDefaultColor(name) {
    let hash = 0
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash)
    }
    return colors[Math.abs(hash) % colors.length]
  }

  function getUserColor(userName, _version) {
    const custom = getUserCustomization(userName)
    return custom?.color || getDefaultColor(userName)
  }

  function getUserAvatar(userName, _version) {
    const custom = getUserCustomization(userName)
    return custom?.avatar || ''
  }

  function getNodeCount(userName) {
    return nodes.filter(n => n.user?.name === userName).length
  }

  function getOnlineCount(userName) {
    const userNodes = nodes.filter(n => n.user?.name === userName)
    return userNodes.filter(n => n.online).length
  }

  function formatRelativeDate(dateStr) {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now - date
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

    if (diffDays === 0) return 'today'
    if (diffDays === 1) return 'yesterday'
    if (diffDays < 7) return `${diffDays} days ago`
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`
    return `${Math.floor(diffDays / 365)} years ago`
  }

  // Filtered users
  const filteredUsers = $derived(
    users.filter(u =>
      u.name.toLowerCase().includes(searchQuery.toLowerCase())
    )
  )

  async function createUser() {
    if (!newUserName.trim()) return
    creating = true
    try {
      await apiPost('/api/hs/users', { name: newUserName })
      toast('User created', 'success')
      showCreateModal = false
      newUserName = ''
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  async function renameUser(user) {
    const newName = prompt('New name:', user.name)
    if (!newName || newName === user.name) return
    try {
      await apiPut(`/api/hs/users/${user.name}/rename/${newName}`)
      toast('User renamed', 'success')
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function confirmDeleteUser(user) {
    deletingUser = user
    showDeleteModal = true
  }

  function getUserNodes(userName) {
    return nodes.filter(n => n.user?.name === userName)
  }

  async function deleteUser() {
    if (!deletingUser) return
    deleting = true
    try {
      // First delete all nodes belonging to this user
      const userNodes = getUserNodes(deletingUser.name)
      for (const node of userNodes) {
        await apiDelete(`/api/hs/nodes/${node.id}`)
      }
      // Then delete the user
      await apiDelete(`/api/hs/users/${deletingUser.name}`)
      toast('User and nodes deleted', 'success')
      showDeleteModal = false
      deletingUser = null
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      deleting = false
    }
  }

  function openEditModal(user) {
    editingUser = user
    selectedColor = getUserColor(user.name)
    selectedAvatar = getUserAvatar(user.name)
    showEditModal = true
  }

  function saveCustomization() {
    if (!editingUser) return
    saveUserCustomization(editingUser.name, {
      color: selectedColor,
      avatar: selectedAvatar
    })
    customizationVersion++ // Trigger reactivity
    showEditModal = false
    editingUser = null
    toast('User customization saved', 'success')
  }
</script>

<div class="space-y-4">
  <!-- Info Card -->
  <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
    <div class="flex items-start gap-3">
      <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
        <Icon name="users" size={18} class="text-primary" />
      </div>
      <div class="flex-1 min-w-0">
        <h3 class="text-sm font-medium text-foreground mb-1">Users</h3>
        <p class="text-xs text-muted-foreground leading-relaxed">
          Organize your network with users. Each user can own multiple nodes and have their own
          pre-auth keys. Customize avatars and colors for easy identification.
        </p>
      </div>
    </div>
  </div>

  <!-- Toolbar -->
  <Toolbar bind:search={searchQuery} placeholder="Search users..." />

  <!-- Users grid -->
  {#if filteredUsers.length > 0}
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {#each filteredUsers as user (user.id)}
        {@const nodeCount = getNodeCount(user.name)}
        {@const onlineCount = getOnlineCount(user.name)}
        {@const userColor = getUserColor(user.name, customizationVersion)}
        {@const userAvatar = getUserAvatar(user.name, customizationVersion)}

        <div class="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors shadow-sm">
          <!-- Header -->
          <div class="flex items-center gap-3 p-3">
            <div
              class="w-10 h-10 rounded-full flex items-center justify-center text-lg font-medium text-white flex-shrink-0"
              style="background-color: {userColor}"
            >
              {userAvatar || user.name.charAt(0).toUpperCase()}
            </div>
            <div class="flex-1 min-w-0">
              <div class="text-sm font-semibold text-foreground truncate">{user.name}</div>
              <div class="text-[11px] text-muted-foreground flex items-center gap-1">
                <Icon name="clock" size={11} />
                {formatRelativeDate(user.createdAt)}
              </div>
            </div>
          </div>

          <!-- Stats grid -->
          <div class="grid grid-cols-2 gap-x-3 border-t border-border px-3 py-2.5 text-[11px]">
            <div class="flex items-center gap-1.5">
              <Icon name="server" size={12} class="text-slate-400 dark:text-zinc-600" />
              <span class="text-slate-600 dark:text-zinc-400">{nodeCount} nodes</span>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="h-1.5 w-1.5 rounded-full {onlineCount > 0 ? 'bg-emerald-500' : 'bg-slate-400 dark:bg-zinc-600'}"></span>
              <span class="{onlineCount > 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500 dark:text-zinc-500'}">{onlineCount} online</span>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-end gap-0.5 px-2 py-1.5 border-t border-border bg-muted/30">
            <button
              onclick={() => openEditModal(user)}
              class="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors cursor-pointer"
              title="Customize"
            >
              <Icon name="settings" size={14} />
            </button>
            <button
              onclick={() => renameUser(user)}
              class="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors cursor-pointer"
              title="Rename"
            >
              <Icon name="edit" size={14} />
            </button>
            <button
              onclick={() => confirmDeleteUser(user)}
              class="p-1.5 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors cursor-pointer"
              title="Delete"
            >
              <Icon name="trash" size={14} />
            </button>
          </div>
        </div>
      {/each}

      <!-- Add user card -->
      <article
        onclick={() => showCreateModal = true}
        class="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-slate-300 bg-slate-50 p-4 text-center text-xs text-slate-500 transition hover:border-slate-400 hover:bg-slate-100 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-300 dark:hover:border-zinc-600 dark:hover:bg-zinc-800/70"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200/80 text-slate-600 dark:bg-zinc-700 dark:text-zinc-100">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-slate-700 dark:text-zinc-100">Add new user</div>
        <p class="max-w-[200px] text-slate-400 dark:text-zinc-500">
          Create users to organize nodes and generate auth keys
        </p>
      </article>
    </div>
  {:else if users.length > 0}
    <!-- No search results -->
    <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
      <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
        <Icon name="search" size={20} />
      </div>
      <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No users found</h4>
      <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">Try a different search term</p>
    </div>
  {/if}

  {#if filteredUsers.length === 0 && users.length === 0}
    <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-slate-50 py-12 text-center dark:border-zinc-700 dark:bg-zinc-900/70">
      <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-200/80 text-slate-500 dark:bg-zinc-700 dark:text-zinc-400">
        <Icon name="users" size={20} />
      </div>
      <h4 class="mt-3 text-sm font-medium text-slate-700 dark:text-zinc-200">No users yet</h4>
      <p class="mt-1 text-xs text-slate-500 dark:text-zinc-500">
        Create users to organize nodes and generate auth keys
      </p>
      <Button onclick={() => showCreateModal = true} size="sm" class="mt-4">
        <Icon name="plus" size={14} />
        Add User
      </Button>
    </div>
  {/if}
</div>

<!-- Create User Modal -->
<Modal bind:open={showCreateModal} title="Create User" size="sm">
  <Input
    bind:value={newUserName}
    label="Username"
    placeholder="Enter username"
  />

  {#snippet footer()}
    <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
    <Button onclick={createUser} disabled={creating}>
      {creating ? 'Creating...' : 'Create'}
    </Button>
  {/snippet}
</Modal>

<!-- Edit User Modal -->
<Modal bind:open={showEditModal} title={editingUser ? `Customize "${editingUser.name}"` : 'Customize User'} size="sm">
  {#if editingUser}
    <div class="space-y-6">
      <div>
        <label class="kt-label">Color</label>
        <div class="grid grid-cols-8 gap-2">
          {#each colors as color}
            <button
              type="button"
              onclick={() => selectedColor = color}
              class="w-8 h-8 rounded-full transition-transform hover:scale-110 {selectedColor === color ? 'ring-2 ring-offset-2 ring-primary ring-offset-card' : ''}"
              style="background-color: {color}"
            ></button>
          {/each}
        </div>
      </div>

      <div>
        <label class="kt-label">Avatar (optional)</label>
        <div class="grid grid-cols-8 gap-2">
          <button
            type="button"
            onclick={() => selectedAvatar = ''}
            class="w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium text-white transition-transform hover:scale-110 {!selectedAvatar ? 'ring-2 ring-offset-2 ring-primary ring-offset-card' : ''}"
            style="background-color: {selectedColor}"
          >
            {editingUser.name.charAt(0).toUpperCase()}
          </button>
          {#each emojis as emoji}
            <button
              type="button"
              onclick={() => selectedAvatar = emoji}
              class="w-8 h-8 rounded-full bg-muted flex items-center justify-center text-lg transition-transform hover:scale-110 {selectedAvatar === emoji ? 'ring-2 ring-offset-2 ring-primary ring-offset-card' : ''}"
            >
              {emoji}
            </button>
          {/each}
        </div>
      </div>

      <div>
        <label class="kt-label">Preview</label>
        <div class="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
          <div
            class="w-12 h-12 rounded-full flex items-center justify-center text-xl font-medium text-white"
            style="background-color: {selectedColor}"
          >
            {selectedAvatar || editingUser.name.charAt(0).toUpperCase()}
          </div>
          <span class="font-medium text-foreground">{editingUser.name}</span>
        </div>
      </div>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => showEditModal = false} variant="secondary">Cancel</Button>
    <Button onclick={saveCustomization}>Save</Button>
  {/snippet}
</Modal>

<!-- Delete Confirmation Modal -->
<Modal bind:open={showDeleteModal} title="Delete User" size="sm">
  {#if deletingUser}
    {@const userNodeCount = getNodeCount(deletingUser.name)}
    <div class="kt-alert kt-alert-destructive">
      <Icon name="alert-triangle" size={18} />
      <div>
        <p class="font-medium">Delete {deletingUser.name}?</p>
        <p class="text-sm opacity-80 mt-0.5">
          {#if userNodeCount > 0}
            This will also delete {userNodeCount} node{userNodeCount > 1 ? 's' : ''}. This action cannot be undone.
          {:else}
            This action cannot be undone.
          {/if}
        </p>
      </div>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => { showDeleteModal = false; deletingUser = null }} variant="secondary" disabled={deleting}>Cancel</Button>
    <Button onclick={deleteUser} variant="destructive" icon="trash" disabled={deleting}>
      {deleting ? 'Deleting...' : 'Delete'}
    </Button>
  {/snippet}
</Modal>
