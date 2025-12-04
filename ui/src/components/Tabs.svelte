<script>
  import Icon from './Icon.svelte'

  let {
    tabs = [],
    activeTab = $bindable(''),
    class: className = ''
  } = $props()

  // Set initial active tab if not set
  $effect(() => {
    if (!activeTab && tabs.length > 0) {
      activeTab = tabs[0].id
    }
  })
</script>

<div class="flex border-b border-border overflow-x-auto {className}">
  {#each tabs as tab}
    <button
      onclick={() => activeTab = tab.id}
      class="flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors relative
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
