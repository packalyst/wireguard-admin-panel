<script>
  import { onMount, onDestroy } from 'svelte'
  import { Chart, registerables } from 'chart.js'

  Chart.register(...registerables)

  let {
    type = 'line',
    data = { labels: [], datasets: [] },
    options = {},
    class: className = ''
  } = $props()

  let canvas
  let chart

  // Deep clone data to avoid Svelte 5 proxy conflicts with Chart.js
  function cloneData(d) {
    return JSON.parse(JSON.stringify(d))
  }

  function createChart() {
    if (chart) {
      chart.destroy()
    }

    const ctx = canvas.getContext('2d')

    // Modern dark theme options
    const defaultOptions = {
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        duration: 400,
        easing: 'easeOutQuart'
      },
      interaction: {
        mode: 'index',
        intersect: false
      },
      scales: {
        x: {
          border: {
            display: false
          },
          grid: {
            display: false
          },
          ticks: {
            color: 'rgba(255, 255, 255, 0.5)',
            font: {
              size: 11
            },
            maxRotation: 0
          }
        },
        y: {
          border: {
            display: false
          },
          grid: {
            color: 'rgba(255, 255, 255, 0.06)',
            drawTicks: false
          },
          ticks: {
            color: 'rgba(255, 255, 255, 0.5)',
            font: {
              size: 11
            },
            padding: 8
          }
        }
      },
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          titleColor: 'rgba(255, 255, 255, 0.9)',
          bodyColor: 'rgba(255, 255, 255, 0.8)',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          cornerRadius: 8,
          padding: 12,
          displayColors: true,
          boxPadding: 4
        }
      },
      elements: {
        line: {
          borderWidth: 2
        },
        point: {
          radius: 0,
          hoverRadius: 4,
          hoverBorderWidth: 2
        }
      }
    }

    chart = new Chart(ctx, {
      type,
      data: cloneData(data),
      options: { ...defaultOptions, ...options }
    })
  }

  // Update chart when data changes
  $effect(() => {
    if (chart && data) {
      chart.data = cloneData(data)
      chart.update('none') // 'none' for no animation on updates
    }
  })

  onMount(() => {
    createChart()
  })

  onDestroy(() => {
    if (chart) {
      chart.destroy()
    }
  })
</script>

<div class="relative {className}">
  <canvas bind:this={canvas}></canvas>
</div>
