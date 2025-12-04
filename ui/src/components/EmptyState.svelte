<script>
  import Icon from './Icon.svelte'

  let {
    icon = 'inbox',
    title = 'No items',
    description = '',
    compact = false
  } = $props()
</script>

<div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-muted/30 {compact ? 'py-8' : 'py-12'} text-center">
  <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
    <Icon name={icon} size={20} />
  </div>
  <h4 class="mt-3 text-sm font-medium text-foreground">{title}</h4>
  {#if description}
    <p class="mt-1 text-xs text-muted-foreground">{description}</p>
  {/if}
</div>
