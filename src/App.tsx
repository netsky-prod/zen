import React, { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Toaster } from './components/Toaster'
import { Settings } from './components/Settings'

declare global {
  interface Window {
    __TAURI__: {
      core: {
        invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>
      }
    }
  }
}

interface VlessConfig {
  uuid: string
  address: string
  port: number
  security: string
  transport_type: string
  path: string
  host: string
  name: string
}

interface Profile {
  id: string
  name: string
  config: VlessConfig
}

interface AppStatus {
  singbox_installed: boolean
  singbox_path: string
  downloading: boolean
}

interface TrafficStats {
  rx_bytes: number
  tx_bytes: number
}

interface UpdateInfo {
  available: boolean
  current_version: string
  latest_version: string
  notes?: string | null
  asset_url?: string | null
  sha256?: string | null
  platform: string
  downloaded_path?: string | null
}

function App() {
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [linkInput, setLinkInput] = useState('')
  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  const [singboxInstalled, setSingboxInstalled] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [ping, setPing] = useState<number | null>(null)
  const [traffic, setTraffic] = useState<TrafficStats | null>(null)
  const [isVisible, setIsVisible] = useState(() => !document.hidden)
  const [lastStatusError, setLastStatusError] = useState<string | null>(null)
  const currentProfile = selectedId ? profiles.find(p => p.id === selectedId) : null
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null)
  const [checkingUpdate, setCheckingUpdate] = useState(false)
  const [installingUpdate, setInstallingUpdate] = useState(false)
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('zen-theme')
    return (saved as 'dark' | 'light') || 'dark'
  })
  const [settingsOpen, setSettingsOpen] = useState(false)

  const invoke = window.__TAURI__?.core?.invoke

  useEffect(() => {
    checkSetup()
    loadProfiles()

    const handleVisibility = () => setIsVisible(!document.hidden)
    document.addEventListener('visibilitychange', handleVisibility)
    return () => document.removeEventListener('visibilitychange', handleVisibility)
  }, [])

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('zen-theme', theme)
  }, [theme])

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark')
  }

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success('Copied')
    } catch {
      toast.error('Failed to copy')
    }
  }

  // Reset ping and traffic when disconnected, poll traffic when connected
  useEffect(() => {
    if (!isConnected || !isVisible) {
      setPing(null)
      setTraffic(null)
      return
    }

    // Poll traffic stats every second when connected
    const pollTraffic = async () => {
      if (!invoke) return
       // Skip background polling when page is hidden to avoid needless work
      if (document.hidden) return
      try {
        const stats = await invoke<TrafficStats>('get_traffic_stats')
        setTraffic(stats)
      } catch {
        // Interface might not be ready yet
      }
    }

    pollTraffic()
    const interval = setInterval(pollTraffic, 1000)
    return () => clearInterval(interval)
  }, [isConnected, isVisible])

  const handlePing = async () => {
    if (!invoke || !isConnected) return
    const profile = profiles.find((p: Profile) => p.id === selectedId)
    if (!profile) return

    try {
      const ms = await invoke<number>('ping_server', { address: profile.config.address })
      setPing(ms)
    } catch {
      setPing(null)
    }
  }

  const checkSetup = async () => {
    if (!invoke) return
    try {
      const status = await invoke<AppStatus>('check_singbox_installed')
      setSingboxInstalled(status.singbox_installed)
    } catch (e) {
      toast.error('Failed to check setup', {
        description: String(e),
      })
    }
  }

  const loadProfiles = async () => {
    if (!invoke) return
    try {
      const loaded = await invoke<Profile[]>('load_profiles')
      setProfiles(loaded)
      if (loaded.length > 0 && !selectedId) {
        setSelectedId(loaded[0].id)
      }
    } catch (e) {
      toast.error('Failed to load profiles', {
        description: String(e),
      })
    }
  }

  const handleDownloadSingbox = async () => {
    if (!invoke) return
    setError(null)
    setIsDownloading(true)

    try {
      await invoke<string>('download_singbox')
      setSingboxInstalled(true)
    } catch (e) {
      setError(String(e))
    } finally {
      setIsDownloading(false)
    }
  }

  const handleAddProfile = async () => {
    if (!invoke || !linkInput.trim()) return
    setError(null)

    try {
      const config = await invoke<VlessConfig>('parse_vless_link', { link: linkInput })
      if (!config.address || !config.uuid || !config.port || config.port < 1 || config.port > 65535) {
        setError('Invalid profile data (address/port/uuid)')
        return
      }
      const profile: Profile = {
        id: crypto.randomUUID(),
        name: config.name,
        config,
      }
      await invoke('save_profile', { profile })
      setLinkInput('')
      await loadProfiles()
      setSelectedId(profile.id)
    } catch (e) {
      setError(String(e))
    }
  }

  const handleCheckUpdate = async () => {
    if (!invoke) return
    setCheckingUpdate(true)
    try {
      const info = await invoke<UpdateInfo>('check_for_update')
      setUpdateInfo(info)
      if (info.available) {
        toast.info(`Update ${info.latest_version} available`)
      } else {
        toast.success('No updates available')
      }
    } catch (e) {
      toast.error('Failed to check updates', { description: String(e) })
    } finally {
      setCheckingUpdate(false)
    }
  }

  const handleInstallUpdate = async () => {
    if (!invoke) return
    setInstallingUpdate(true)
    try {
      const info = await invoke<UpdateInfo>('install_update')
      setUpdateInfo(info)
      if (info.downloaded_path) {
        toast.success('Update downloaded', {
          description: info.platform.startsWith('windows')
            ? 'Installer launched (if allowed)'
            : `Saved to: ${info.downloaded_path}`,
        })
      } else {
        toast.error('Download failed or no asset for platform')
      }
    } catch (e) {
      toast.error('Failed to install update', { description: String(e) })
    } finally {
      setInstallingUpdate(false)
    }
  }

  const handleDuplicateProfile = async () => {
    if (!invoke || !selectedId) return
    const original = profiles.find((p: Profile) => p.id === selectedId)
    if (!original) return

    const copy: Profile = {
      id: crypto.randomUUID(),
      name: `${original.name} (copy)`,
      config: { ...original.config, name: `${original.config.name} (copy)` },
    }

    try {
      await invoke('save_profile', { profile: copy })
      await loadProfiles()
      setSelectedId(copy.id)
    } catch (e) {
      setError(String(e))
    }
  }

  const handleDeleteProfile = async (id: string, e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation()
    if (!invoke) return

    try {
      await invoke('delete_profile', { id })
      if (selectedId === id) {
        setSelectedId(null)
      }
      await loadProfiles()
    } catch (e) {
      setError(String(e))
    }
  }

  const handleConnect = async () => {
    if (!invoke) return
    setError(null)
    setIsConnecting(true)

    try {
      if (isConnected) {
        await invoke('stop_singbox')
        setIsConnected(false)
        setLastStatusError(null)
      } else {
        if (!currentProfile) {
          setError('Select a profile first')
          setIsConnecting(false)
          return
        }
        await invoke('start_singbox', { config: currentProfile.config })
        setIsConnected(true)
        setLastStatusError(null)
      }
    } catch (e) {
      setError(String(e))
      setLastStatusError(String(e))
      setIsConnected(false)
    } finally {
      setIsConnecting(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleAddProfile()
    }
  }

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  const getStatusText = () => {
    if (isConnecting) return 'Connecting...'
    if (isConnected) {
      return ping !== null ? `Protected • ${ping}ms` : 'Protected'
    }
    if (lastStatusError) return 'Error'
    return 'Not Connected'
  }

  const statusBadgeClass = () => {
    if (isConnecting) return 'badge badge-warn'
    if (isConnected) return 'badge badge-ok'
    if (lastStatusError) return 'badge badge-error'
    return 'badge'
  }

  return (
    <div className="app">
      <header className="header">
        <button
          className="btn-icon settings-btn"
          onClick={() => setSettingsOpen(true)}
          title="Settings"
        >
          ⚙️
        </button>
        <h1>Zen</h1>
        <div className="subtitle">Key to Enlightenment</div>
        <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme">
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
      </header>

      <div className="connection-status">
        <div className={`status-indicator ${isConnected ? 'connected' : ''} ${isConnecting ? 'connecting' : ''}`} />
        <div className="status-info">
          <div className="status-label">Status</div>
          <div className={`status-text ${isConnected ? 'connected' : ''}`}>
            {getStatusText()}
          </div>
          <div className={statusBadgeClass()}>
            {isConnecting ? 'Connecting' : isConnected ? 'Connected' : lastStatusError ? 'Error' : 'Idle'}
          </div>
        </div>
        {isConnected && (
          <button className="btn-ping" onClick={handlePing}>
            Ping
          </button>
        )}
      </div>

      {lastStatusError && (
        <div className="status-error">
          <div className="status-error-text">{lastStatusError}</div>
          <button className="btn-secondary" onClick={() => copyToClipboard(lastStatusError)}>
            Copy error
          </button>
        </div>
      )}

      {isConnected && traffic && (
        <div className="traffic-stats">
          <div className="traffic-item">
            <span className="traffic-arrow down">↓</span>
            <span className="traffic-label">Download</span>
            <span className="traffic-value">{formatBytes(traffic.rx_bytes)}</span>
          </div>
          <div className="traffic-item">
            <span className="traffic-arrow up">↑</span>
            <span className="traffic-label">Upload</span>
            <span className="traffic-value">{formatBytes(traffic.tx_bytes)}</span>
          </div>
        </div>
      )}

      {!singboxInstalled && (
        <div className="setup-banner">
          <h3>Initial Setup Required</h3>
          <p>Download the VPN engine to get started</p>
          <button
            className="btn-primary btn-download"
            onClick={handleDownloadSingbox}
            disabled={isDownloading}
          >
            {isDownloading ? (
              <>
                <span className="spinner" />
                Downloading...
              </>
            ) : (
              'Download Engine'
            )}
          </button>
        </div>
      )}

      <div className="card add-profile">
        <div className="input-group">
          <input
            type="text"
            placeholder="Paste vless:// link"
            value={linkInput}
            onChange={(e) => setLinkInput(e.target.value)}
            onKeyPress={handleKeyPress}
          />
          <button className="btn-primary" onClick={handleAddProfile}>
            Add
          </button>
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      <div className="profiles-section">
        <div className="profiles-header">
          <h3>Profiles</h3>
        </div>

        {profiles.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔐</div>
            <p>Add a profile to get started</p>
          </div>
        ) : (
          <div className="profiles-list">
            {profiles.map((profile: Profile) => (
              <div
                key={profile.id}
                className={`profile-item ${selectedId === profile.id ? 'selected' : ''}`}
                onClick={() => setSelectedId(profile.id)}
              >
                <div className="profile-radio" />
                <div className="profile-info">
                  <div className="profile-name">{profile.name}</div>
                  <div className="profile-address">
                    {profile.config.address}:{profile.config.port}
                  </div>
                </div>
                <button
                  className="btn-icon"
                  onClick={(e) => handleDeleteProfile(profile.id, e)}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="profiles-actions">
        <button
          className="btn-secondary"
          onClick={handleDuplicateProfile}
          disabled={!selectedId}
        >
          Duplicate
        </button>
      </div>

      <div className="card updates-card">
        <div className="updates-header">
          <div>
            <div className="updates-title">Updates</div>
            <div className="updates-subtitle">
              {updateInfo
                ? `Current ${updateInfo.current_version} / Latest ${updateInfo.latest_version}`
                : 'Check for available updates'}
            </div>
          </div>
          <button
            className="btn-secondary"
            onClick={handleCheckUpdate}
            disabled={checkingUpdate}
          >
            {checkingUpdate ? 'Checking...' : 'Check for updates'}
          </button>
        </div>

        {updateInfo?.available && (
          <div className="updates-available">
            <div className="updates-version">
              New version {updateInfo.latest_version} ({updateInfo.platform})
            </div>
            {updateInfo.notes && <div className="updates-notes">{updateInfo.notes}</div>}
            <button
              className="btn-primary"
              onClick={handleInstallUpdate}
              disabled={installingUpdate}
            >
              {installingUpdate ? 'Installing...' : 'Install'}
            </button>
            {updateInfo.downloaded_path && (
              <div className="updates-path">Saved to: {updateInfo.downloaded_path}</div>
            )}
          </div>
        )}
      </div>

      <button
        className={`btn-primary btn-connect ${isConnected ? 'connected' : ''}`}
        onClick={handleConnect}
        disabled={isConnecting || (!isConnected && !selectedId) || !singboxInstalled}
      >
        {isConnecting ? (
          <>
            <span className="spinner" />
            {isConnected ? 'Disconnecting...' : 'Connecting...'}
          </>
        ) : isConnected ? (
          `Disconnect${currentProfile ? ` (${currentProfile.name})` : ''}`
        ) : (
          currentProfile ? `Connect to ${currentProfile.name}` : 'Connect'
        )}
      </button>
      <Toaster theme={theme} />
      <Settings
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        serverIp={selectedId ? profiles.find(p => p.id === selectedId)?.config.address : undefined}
        isConnected={isConnected}
      />
    </div>
  )
}

export default App
