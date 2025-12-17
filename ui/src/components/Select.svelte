<script>
  let {
    value = $bindable(''),
    size = 'sm',
    disabled = false,
    class: className = '',
    onchange = undefined,
    ...restProps
  } = $props();

  // Size classes mapping (sm is default)
  const sizeClasses = {
    sm: 'kt-select-sm',
    lg: ''
  };
  const sizeClass = sizeClasses[size] || sizeClasses.sm;
</script>

<select
  bind:value
  {disabled}
  {onchange}
  class="kt-select {sizeClass} w-full sm:w-auto sm:min-w-32 {className}"
  {...restProps}
>
  <slot />
</select>
