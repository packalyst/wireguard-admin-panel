<script>
  import Icon from './Icon.svelte'

  let {
    page = $bindable(1),
    perPage = $bindable(25),
    total = 0,
    onPageChange = () => {},
    onPerPageChange = () => {}
  } = $props()

  const totalPages = $derived(Math.ceil(total / perPage) || 1)
  const offset = $derived((page - 1) * perPage)

  function goToPage(p) {
    if (p < 1 || p > totalPages) return
    page = p
    onPageChange(p)
  }

  function changePerPage(newPerPage) {
    perPage = newPerPage
    page = 1
    onPerPageChange(newPerPage)
  }

  function getPageNumbers() {
    const pages = []
    const maxVisible = 5

    if (totalPages <= maxVisible + 2) {
      for (let i = 1; i <= totalPages; i++) pages.push(i)
    } else {
      pages.push(1)

      let start = Math.max(2, page - 1)
      let end = Math.min(totalPages - 1, page + 1)

      if (page <= 3) {
        end = Math.min(totalPages - 1, maxVisible)
      } else if (page >= totalPages - 2) {
        start = Math.max(2, totalPages - maxVisible + 1)
      }

      if (start > 2) pages.push('...')
      for (let i = start; i <= end; i++) pages.push(i)
      if (end < totalPages - 1) pages.push('...')

      if (totalPages > 1) pages.push(totalPages)
    }

    return pages
  }
</script>

<div class="kt-datatable-toolbar">
  <div class="kt-datatable-info">
    <div class="kt-datatable-length">
      <span>Show</span>
      <select
        value={perPage}
        onchange={(e) => changePerPage(parseInt(e.target.value))}
        class="kt-input kt-input-sm w-16"
      >
        <option value={10}>10</option>
        <option value={25}>25</option>
        <option value={50}>50</option>
        <option value={100}>100</option>
      </select>
      <span>entries</span>
    </div>
    <span class="hidden sm:inline">
      Showing {offset + 1} to {Math.min(offset + perPage, total)} of {total.toLocaleString()} entries
    </span>
  </div>

  <div class="kt-datatable-pagination">
    <button
      onclick={() => goToPage(1)}
      disabled={page === 1}
      class="kt-datatable-pagination-button"
    >
      <Icon name="chevrons-left" size={16} />
    </button>
    <button
      onclick={() => goToPage(page - 1)}
      disabled={page === 1}
      class="kt-datatable-pagination-button kt-datatable-pagination-prev"
    >
      <Icon name="chevron-left" size={16} />
    </button>

    {#each getPageNumbers() as p}
      {#if p === '...'}
        <span class="kt-datatable-pagination-button kt-datatable-pagination-more">
          <Icon name="dots" size={16} />
        </span>
      {:else}
        <button
          onclick={() => goToPage(p)}
          class="kt-datatable-pagination-button {p === page ? 'active' : ''}"
        >
          {p}
        </button>
      {/if}
    {/each}

    <button
      onclick={() => goToPage(page + 1)}
      disabled={page === totalPages}
      class="kt-datatable-pagination-button kt-datatable-pagination-next"
    >
      <Icon name="chevron-right" size={16} />
    </button>
    <button
      onclick={() => goToPage(totalPages)}
      disabled={page === totalPages}
      class="kt-datatable-pagination-button"
    >
      <Icon name="chevrons-right" size={16} />
    </button>
  </div>
</div>
