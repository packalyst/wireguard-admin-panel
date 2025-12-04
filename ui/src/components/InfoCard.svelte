<script>
  import Icon from './Icon.svelte'

  let { icon = 'info', title, description, children } = $props()
</script>

<div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
  <div class="flex items-start gap-3">
    <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
      <Icon name={icon} size={18} class="text-primary" />
    </div>
    <div class="flex-1 min-w-0">
      <h3 class="text-sm font-medium text-foreground mb-1">{title}</h3>
      <p class="text-xs text-muted-foreground leading-relaxed">{description}</p>
    </div>
    {#if children}
      {@render children()}
    {/if}
  </div>
</div>
