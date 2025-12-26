import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { initializeNotifications } from './services/notifications'
import './styles.css'

// Initialize VPN notification listeners
initializeNotifications()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
