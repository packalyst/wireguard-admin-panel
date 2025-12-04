import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
// Import directly from component path to avoid loading all KTUI components
import { KTModal } from '@keenthemes/ktui/lib/esm/components/modal'
import { KTToast } from '@keenthemes/ktui/lib/esm/components/toast'

// Make KTUI components globally available
window.KTModal = KTModal
window.KTToast = KTToast
KTModal.init()

const app = mount(App, {
  target: document.getElementById('app'),
})

export default app
