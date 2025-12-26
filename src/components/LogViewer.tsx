import { useState, useEffect, useRef, useCallback } from 'react'
import { toast } from 'sonner'

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'panic'

interface LogEntry {
  timestamp: number
  level: LogLevel
  message: string
  source: string
}

interface LogsResponse {
  entries: LogEntry[]
  total_count: number
  filter_level: string
}

interface LogViewerProps {
  /** Maximum number of logs to display */
  maxDisplayCount?: number
  /** Polling interval in milliseconds (0 to disable) */
  pollInterval?: number
  /** Whether to auto-scroll to bottom on new logs */
  autoScroll?: boolean
}

const LOG_LEVELS: LogLevel[] = ['debug', 'info', 'warn', 'error', 'fatal', 'panic']

const LOG_LEVEL_COLORS: Record<LogLevel, string> = {
  debug: 'var(--log-debug, #888)',
  info: 'var(--log-info, #3b82f6)',
  warn: 'var(--log-warn, #f59e0b)',
  error: 'var(--log-error, #ef4444)',
  fatal: 'var(--log-fatal, #dc2626)',
  panic: 'var(--log-panic, #7f1d1d)',
}

export function LogViewer({
  maxDisplayCount = 100,
  pollInterval = 2000,
  autoScroll = true,
}: LogViewerProps) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [filterLevel, setFilterLevel] = useState<LogLevel>('info')
  const [isExporting, setIsExporting] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [copying, setCopying] = useState(false)
  const logContainerRef = useRef<HTMLDivElement>(null)
  const lastTimestampRef = useRef<number>(0)

  const invoke = window.__TAURI__?.core?.invoke

  const fetchLogs = useCallback(async () => {
    if (!invoke || isPaused || document.hidden) return

    try {
      const response = await invoke<LogsResponse>('get_logs', {
        count: maxDisplayCount,
      })
      setLogs(response.entries)
      setFilterLevel(response.filter_level as LogLevel)

      // Update last timestamp for new log detection
      if (response.entries.length > 0) {
        const lastEntry = response.entries[response.entries.length - 1]
        if (lastEntry.timestamp > lastTimestampRef.current) {
          lastTimestampRef.current = lastEntry.timestamp
          // Auto-scroll to bottom on new logs
          if (autoScroll && logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
          }
        }
      }
    } catch {
      // Silently fail on polling - don't spam user with errors
    }
  }, [invoke, isPaused, maxDisplayCount, autoScroll])

  const handleSetLogLevel = async (level: LogLevel) => {
    if (!invoke) return

    try {
      await invoke('set_log_level', { level })
      setFilterLevel(level)
      // Immediately refresh logs after level change
      await fetchLogs()
    } catch (e) {
      toast.error('Failed to set log level', {
        description: String(e),
      })
    }
  }

  const quickFilterErrors = async () => {
    await handleSetLogLevel('error')
  }

  const handleExportLogs = async () => {
    if (!invoke) return

    setIsExporting(true)
    try {
      const filePath = await invoke<string>('export_logs', {})
      toast.success('Logs exported successfully', {
        description: `Saved to: ${filePath}`,
      })
    } catch (e) {
      toast.error('Failed to export logs', {
        description: String(e),
      })
    } finally {
      setIsExporting(false)
    }
  }

  const handleClearLogs = () => {
    setLogs([])
    lastTimestampRef.current = 0
  }

  const handleCopyDisplayed = async () => {
    if (logs.length === 0) return
    setCopying(true)
    try {
      const text = logs
        .map(l => `[${l.level.toUpperCase()}] ${new Date(l.timestamp).toISOString()} (${l.source}) ${l.message}`)
        .join('\n')
      await navigator.clipboard.writeText(text)
      toast.success('Logs copied')
    } catch (e) {
      toast.error('Failed to copy logs', {
        description: String(e),
      })
    } finally {
      setCopying(false)
    }
  }

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  // Initial fetch and polling
  useEffect(() => {
    fetchLogs()

    if (pollInterval > 0) {
      const interval = setInterval(fetchLogs, pollInterval)
      return () => clearInterval(interval)
    }
  }, [fetchLogs, pollInterval])

  return (
    <div className="log-viewer">
      <div className="log-viewer-header">
        <div className="log-viewer-controls">
          <select
            className="log-level-select"
            value={filterLevel}
            onChange={(e) => handleSetLogLevel(e.target.value as LogLevel)}
          >
            {LOG_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level.charAt(0).toUpperCase() + level.slice(1)}
              </option>
            ))}
          </select>

          <button
            className="btn-secondary log-quick-errors"
            onClick={quickFilterErrors}
            title="Show errors only"
          >
            Errors only
          </button>

          <button
            className={`btn-icon log-pause-btn ${isPaused ? 'paused' : ''}`}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? 'Resume' : 'Pause'}
          >
            {isPaused ? '▶' : '⏸'}
          </button>

          <button
            className="btn-icon log-clear-btn"
            onClick={handleClearLogs}
            title="Clear display"
          >
            🗑
          </button>

          <button
            className="btn-secondary log-export-btn"
            onClick={handleExportLogs}
            disabled={isExporting}
          >
            {isExporting ? 'Exporting...' : 'Export'}
          </button>

          <button
            className="btn-secondary log-copy-btn"
            onClick={handleCopyDisplayed}
            disabled={logs.length === 0 || copying}
            title="Copy displayed logs"
          >
            {copying ? 'Copying...' : 'Copy'}
          </button>
        </div>
      </div>

      <div className="log-viewer-content" ref={logContainerRef}>
        {logs.length === 0 ? (
          <div className="log-viewer-empty">
            <p>No logs to display</p>
            <p className="log-viewer-hint">
              Logs will appear here when the VPN is running
            </p>
          </div>
        ) : (
          <div className="log-entries">
            {logs.map((entry, index) => (
              <div
                key={`${entry.timestamp}-${index}`}
                className={`log-entry log-level-${entry.level}`}
              >
                <div className="log-entry-header">
                  <span
                    className="log-level-badge"
                    style={{ backgroundColor: LOG_LEVEL_COLORS[entry.level] }}
                  >
                    {entry.level.toUpperCase()}
                  </span>
                  <span className="log-timestamp">
                    {formatTimestamp(entry.timestamp)}
                  </span>
                  <span className="log-source">{entry.source}</span>
                </div>
                <div className="log-message">{entry.message}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
