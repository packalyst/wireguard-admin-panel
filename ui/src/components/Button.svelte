<script>
  import Icon from './Icon.svelte';

  let {
    variant = 'primary',
    size = 'default',
    icon = undefined,
    iconOnly = false,
    disabled = false,
    type = 'button',
    class: className = '',
    onclick = undefined,
    children,
    ...restProps
  } = $props();

  const variantClasses = {
    primary: '',
    secondary: 'kt-btn-secondary',
    destructive: 'kt-btn-destructive',
    outline: 'kt-btn-outline',
    ghost: 'kt-btn-ghost',
    mono: 'kt-btn-mono'
  };

  const sizeClasses = {
    default: '',
    sm: 'kt-btn-sm',
    xs: 'kt-btn-xs'
  };

  const classes = [
    'kt-btn',
    variantClasses[variant],
    sizeClasses[size],
    iconOnly && 'kt-btn-icon',
    className
  ].filter(Boolean).join(' ');
</script>

<button
  {type}
  {disabled}
  {onclick}
  class={classes}
  {...restProps}
>
  {#if icon}
    <Icon name={icon} size={size === 'xs' ? 12 : 14} />
  {/if}
  {#if !iconOnly}
    {@render children?.()}
  {/if}
</button>
