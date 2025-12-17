<script>
  import Icon from './Icon.svelte'
  import { onMount } from 'svelte'

  let {
    tabs = [],
    activeTab = $bindable(''),
    urlKey = '',  // If set, persists tab to URL hash (e.g., urlKey="tab" -> #tab=routers)
    class: className = ''
  } = $props()

  // Read initial tab from URL hash if urlKey is set
  onMount(() => {
    if (urlKey && typeof window !== 'undefined') {
      const hash = window.location.hash.slice(1) // Remove #
      const params = new URLSearchParams(hash)
      const tabFromUrl = params.get(urlKey)
      if (tabFromUrl && tabs.some(t => t.id === tabFromUrl)) {
        activeTab = tabFromUrl
      }
    }
  })

  // Set initial active tab if not set
  $effect(() => {
    if (!activeTab && tabs.length > 0) {
      activeTab = tabs[0].id
    }
  })

  function selectTab(tabId) {
    activeTab = tabId

    // Update URL hash if urlKey is set
    if (urlKey && typeof window !== 'undefined') {
      const hash = window.location.hash.slice(1)
      const params = new URLSearchParams(hash)
      params.set(urlKey, tabId)
      window.history.replaceState(null, '', '#' + params.toString())
    }
  }
</script>

<div class="flex border-b border-border overflow-x-auto {className}">
  {#each tabs as tab}
    <button
      onclick={() => selectTab(tab.id)}
      class="flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors relative cursor-pointer
        {activeTab === tab.id ? 'text-primary' : 'text-muted-foreground hover:text-foreground'}"
    >
      {#if tab.icon}
        <Icon name={tab.icon} size={16} />
      {/if}
      {tab.label}
      {#if tab.badge !== undefined}
        <span class="px-1.5 py-0.5 text-[10px] font-medium rounded-full bg-muted text-muted-foreground">
          {tab.badge}
        </span>
      {/if}
      {#if activeTab === tab.id}
        <div class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary"></div>
      {/if}
    </button>
  {/each}
</div>
