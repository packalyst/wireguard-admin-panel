<script>
  import Icon from './Icon.svelte';

  let {
    type = 'text',
    value = $bindable(''),
    placeholder = '',
    disabled = false,
    readonly = false,
    required = false,
    autocomplete = undefined,
    class: className = '',

    // Label support
    label = undefined,
    labelClass = 'block text-xs font-medium text-foreground mb-1',
    helperText = undefined,
    helperClass = 'text-[10px] text-muted-foreground mt-1',

    // Icon support
    prefixIcon = undefined,
    suffixIcon = undefined,

    // Button support (use snippet for full control)
    prefixButton = undefined,
    suffixButton = undefined,

    // Addon support
    prefixAddon = undefined,
    suffixAddon = undefined,
    prefixAddonIcon = undefined,
    suffixAddonIcon = undefined,

    onkeydown = undefined,
    onclick = undefined,
    oninput = undefined,
    onchange = undefined,
    tooltip = undefined,
    ...restProps
  } = $props();

  // Determine wrapper type
  const hasInputGroup = prefixAddon || suffixAddon || prefixAddonIcon || suffixAddonIcon;
  const hasWrapper = prefixIcon || suffixIcon || prefixButton || suffixButton || hasInputGroup;
</script>

{#if label || helperText}
  <div>
    {#if label}
      <label for={restProps.id} class={labelClass}>{label}</label>
    {/if}

    {#if hasInputGroup}
      <div class="kt-input-group {className}">
        {#if prefixAddon}
          <span class="kt-input-addon">{prefixAddon}</span>
        {/if}
        {#if prefixAddonIcon}
          <span class="kt-input-addon kt-input-addon-icon">
            <Icon name={prefixAddonIcon} size={14} />
          </span>
        {/if}
        <input
          bind:value
          {type}
          {placeholder}
          {disabled}
          {readonly}
          {required}
          {autocomplete}
          class="kt-input w-full"
          {onkeydown}
          {onclick}
          {oninput}
          {onchange}
          {...restProps}
        />
        {#if suffixAddonIcon}
          <span class="kt-input-addon kt-input-addon-icon">
            <Icon name={suffixAddonIcon} size={14} />
          </span>
        {/if}
        {#if suffixAddon}
          <span class="kt-input-addon">{suffixAddon}</span>
        {/if}
      </div>
    {:else if hasWrapper}
      <div class="kt-input {className}" data-kt-tooltip={tooltip}>
        {#if prefixIcon}
          <Icon name={prefixIcon} size={14} />
        {/if}
        {#if prefixButton}
          {@render prefixButton()}
        {/if}
        <input
          bind:value
          {type}
          {placeholder}
          {disabled}
          {readonly}
          {required}
          {autocomplete}
          class="w-full"
          {onkeydown}
          {onclick}
          {oninput}
          {onchange}
          {...restProps}
        />
        {#if suffixIcon}
          <Icon name={suffixIcon} size={14} />
        {/if}
        {#if suffixButton}
          {@render suffixButton()}
        {/if}
      </div>
    {:else}
      <input
        bind:value
        {type}
        {placeholder}
        {disabled}
        {readonly}
        {required}
        {autocomplete}
        class="kt-input {className}"
        data-kt-tooltip={tooltip}
        {onkeydown}
        {onclick}
        {oninput}
        {onchange}
        {...restProps}
      />
    {/if}

    {#if helperText}
      <p class={helperClass}>{helperText}</p>
    {/if}
  </div>
{:else}
  {#if hasInputGroup}
    <div class="kt-input-group {className}">
      {#if prefixAddon}
        <span class="kt-input-addon">{prefixAddon}</span>
      {/if}
      {#if prefixAddonIcon}
        <span class="kt-input-addon kt-input-addon-icon">
          <Icon name={prefixAddonIcon} size={14} />
        </span>
      {/if}
      <input
        bind:value
        {type}
        {placeholder}
        {disabled}
        {readonly}
        {required}
        {autocomplete}
        class="kt-input w-full"
        {onkeydown}
        {onclick}
        {oninput}
        {onchange}
        {...restProps}
      />
      {#if suffixAddonIcon}
        <span class="kt-input-addon kt-input-addon-icon">
          <Icon name={suffixAddonIcon} size={14} />
        </span>
      {/if}
      {#if suffixAddon}
        <span class="kt-input-addon">{suffixAddon}</span>
      {/if}
    </div>
  {:else if hasWrapper}
    <div class="kt-input {className}" data-kt-tooltip={tooltip}>
      {#if prefixIcon}
        <Icon name={prefixIcon} size={14} />
      {/if}
      {#if prefixButton}
        {@render prefixButton()}
      {/if}
      <input
        bind:value
        {type}
        {placeholder}
        {disabled}
        {readonly}
        {required}
        {autocomplete}
        class="w-full"
        {onkeydown}
        {onclick}
        {oninput}
        {onchange}
        {...restProps}
      />
      {#if suffixIcon}
        <Icon name={suffixIcon} size={14} />
      {/if}
      {#if suffixButton}
        {@render suffixButton()}
      {/if}
    </div>
  {:else}
    <input
      bind:value
      {type}
      {placeholder}
      {disabled}
      {readonly}
      {required}
      {autocomplete}
      class="kt-input {className}"
      data-kt-tooltip={tooltip}
      {onkeydown}
      {onclick}
      {oninput}
      {onchange}
      {...restProps}
    />
  {/if}
{/if}
