<script>
  let { size = 'md', centered = false } = $props()

  const sizeClasses = {
    xs: 'w-3 h-3',
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
    xl: 'w-10 h-10'
  }
</script>

{#if centered}
  <div class="flex justify-center py-12">
    <div class="{sizeClasses[size] || sizeClasses.md} border-2 border-muted border-t-primary rounded-full animate-spin"></div>
  </div>
{:else}
  <div class="{sizeClasses[size] || sizeClasses.md} border-2 border-muted border-t-primary rounded-full animate-spin"></div>
{/if}
