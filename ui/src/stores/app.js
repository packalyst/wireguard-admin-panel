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

// Current view (persisted)
const savedView = typeof localStorage !== 'undefined' ? localStorage.getItem('hs_view') : 'nodes'
export const currentView = writable(savedView || 'nodes')
currentView.subscribe(value => {
  if (typeof localStorage !== 'undefined' && value) {
    localStorage.setItem('hs_view', value)
  }
})

// Toast using KTUI
export function toast(message, type = 'info') {
  // Map our types to KTUI variants
  const variantMap = {
    success: 'success',
    error: 'destructive',
    warning: 'warning',
    info: 'info'
  }

  // Icons for each type
  const iconMap = {
    success: '<span class="icon-[tabler--check] text-lg"></span>',
    error: '<span class="icon-[tabler--alert-circle] text-lg"></span>',
    warning: '<span class="icon-[tabler--alert-triangle] text-lg"></span>',
    info: '<span class="icon-[tabler--info-circle] text-lg"></span>'
  }

  if (window.KTToast) {
    window.KTToast.show({
      message,
      variant: variantMap[type] || 'info',
      appearance: 'outline',
      progress:true,
      size:'sm',
      position:'bottom-end',
      icon: iconMap[type] || iconMap.info
    })
  }
}

// Base API helper - includes auth token automatically
async function api(endpoint, options = {}) {
  const token = localStorage.getItem('session_token')

  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(endpoint, {
    ...options,
    headers
  })

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
  const token = localStorage.getItem('session_token')
  const headers = {}
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch(endpoint, { headers })
  if (!res.ok) {
    throw new Error(await res.text() || res.statusText)
  }
  return res.text()
}

// Blob fetch (for images like QR codes)
export async function apiGetBlob(endpoint) {
  const token = localStorage.getItem('session_token')
  const headers = {}
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch(endpoint, { headers })
  if (!res.ok) {
    throw new Error(await res.text() || res.statusText)
  }
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
