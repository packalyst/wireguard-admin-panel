<script>
  import Icon from './Icon.svelte'

  let {
    search = $bindable(''),
    placeholder = 'Search...',
    children
  } = $props()
</script>

<div class="rounded-xl border border-slate-200 bg-slate-50/90 px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900/80">
  <div class="flex flex-wrap items-center gap-3">
    <!-- Search input -->
    <div class="kt-input min-w-[160px] max-w-xl flex-1 sm:min-w-[220px]">
      <Icon name="search" size={16} />
      <input
        type="search"
        bind:value={search}
        {placeholder}
        class="kt-input"
      />
    </div>

    <div class="ml-auto"></div>

    <!-- Slot for filters/actions -->
    {#if children}
      {@render children()}
    {/if}
  </div>
</div>
