import { writable } from 'svelte/store'

// Theme
const savedTheme = typeof localStorage !== 'undefined' ? localStorage.getItem('hs_theme') : 'dark'
export const theme = writable(savedTheme || 'dark')
theme.subscribe(value => {
  if (typeof document !== 'undefined') {
    if (value === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.setItem('hs_theme', value)
  }
})

// Valid view IDs for URL routing
export const validViews = ['nodes', 'users', 'firewall', 'routes', 'authkeys', 'apikeys',
                           'traefik', 'adguard', 'docker', 'logs', 'settings', 'about']

// Get initial tab from URL hash (for tab persistence on refresh)
export function getInitialTab(defaultTab, validTabs) {
  if (typeof window === 'undefined') return defaultTab
  const hash = window.location.hash.slice(1)
  const params = new URLSearchParams(hash)
  const tabFromUrl = params.get('tab')
  return tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : defaultTab
}

// Get view from current URL path
function getViewFromPath() {
  if (typeof window === 'undefined') return null
  const path = window.location.pathname.slice(1) // Remove leading /
  return validViews.includes(path) ? path : null
}

// Current view - URL takes priority, then localStorage, then default
const urlView = typeof window !== 'undefined' ? getViewFromPath() : null
const savedView = typeof localStorage !== 'undefined' ? localStorage.getItem('hs_view') : 'nodes'
export const currentView = writable(urlView || savedView || 'nodes')

// Track if we're handling popstate to avoid double-pushing
let handlingPopstate = false

currentView.subscribe(value => {
  if (typeof window !== 'undefined' && value) {
    localStorage.setItem('hs_view', value)
    // Update URL without reload (skip if handling popstate)
    const newPath = '/' + value
    if (!handlingPopstate && window.location.pathname !== newPath) {
      window.history.pushState({ view: value }, '', newPath)
    }
  }
})

// Handle browser back/forward
if (typeof window !== 'undefined') {
  window.addEventListener('popstate', (event) => {
    const view = event.state?.view || getViewFromPath() || 'nodes'
    if (validViews.includes(view)) {
      handlingPopstate = true
      currentView.set(view)
      handlingPopstate = false
    }
  })

  // Set initial history state (replaceState so we don't add to history)
  // Preserve the hash (for tab persistence)
  const initialView = getViewFromPath() || savedView || 'nodes'
  const hash = window.location.hash || ''
  window.history.replaceState({ view: initialView }, '', '/' + initialView + hash)
}

// Toast config (module-level to avoid recreation on each call)
const toastVariants = {
  success: 'success',
  error: 'destructive',
  warning: 'warning',
  info: 'info'
}
const toastIcons = {
  success: '<span class="icon-[tabler--check] text-lg"></span>',
  error: '<span class="icon-[tabler--alert-circle] text-lg"></span>',
  warning: '<span class="icon-[tabler--alert-triangle] text-lg"></span>',
  info: '<span class="icon-[tabler--info-circle] text-lg"></span>'
}

// Toast using KTUI
export function toast(message, type = 'info') {
  if (window.KTToast) {
    window.KTToast.show({
      message,
      variant: toastVariants[type] || 'info',
      appearance: 'outline',
      progress: true,
      size: 'sm',
      position: 'bottom-end',
      icon: toastIcons[type] || toastIcons.info
    })
  }
}

// Auth header helper (consolidated token retrieval)
function getAuthHeaders(extraHeaders = {}) {
  const token = localStorage.getItem('session_token')
  const headers = { ...extraHeaders }
  if (token) headers['Authorization'] = `Bearer ${token}`
  return headers
}

// Base API helper - includes auth token automatically
async function api(endpoint, options = {}) {
  const headers = getAuthHeaders({
    'Content-Type': 'application/json',
    ...options.headers
  })

  const res = await fetch(endpoint, { ...options, headers })

  if (res.ok) {
    const text = await res.text()
    return text ? JSON.parse(text) : {}
  }

  const error = await res.text().catch(() => res.statusText)
  throw new Error(error || res.statusText)
}

// HTTP method helpers
export const apiGet = (endpoint) => api(endpoint, { method: 'GET' })
export const apiPost = (endpoint, data) => api(endpoint, { method: 'POST', body: data ? JSON.stringify(data) : undefined })
export const apiPut = (endpoint, data) => api(endpoint, { method: 'PUT', body: data ? JSON.stringify(data) : undefined })
export const apiDelete = (endpoint, data) => api(endpoint, { method: 'DELETE', body: data ? JSON.stringify(data) : undefined })

// Raw text fetch (for config downloads etc)
export async function apiGetText(endpoint) {
  const res = await fetch(endpoint, { headers: getAuthHeaders() })
  if (!res.ok) throw new Error(await res.text() || res.statusText)
  return res.text()
}

// Blob fetch (for images like QR codes)
export async function apiGetBlob(endpoint) {
  const res = await fetch(endpoint, { headers: getAuthHeaders() })
  if (!res.ok) throw new Error(await res.text() || res.statusText)
  return res.blob()
}

// Generate random secure credentials for AdGuard
export function generateAdguardCredentials() {
  const usernameChars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let username = 'admin_'
  for (let i = 0; i < 8; i++) {
    username += usernameChars.charAt(Math.floor(Math.random() * usernameChars.length))
  }

  const passwordChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
  let password = ''
  for (let i = 0; i < 16; i++) {
    password += passwordChars.charAt(Math.floor(Math.random() * passwordChars.length))
  }

  return { username, password }
}
