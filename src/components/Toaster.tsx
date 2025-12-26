import { Toaster as SonnerToaster } from 'sonner'

interface ToasterProps {
  theme?: 'dark' | 'light'
}

export function Toaster({ theme = 'dark' }: ToasterProps) {
  return (
    <SonnerToaster
      theme={theme}
      position="bottom-right"
      richColors
      closeButton
      toastOptions={{
        style: {
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          color: 'var(--text-primary)',
        },
        className: 'zen-toast',
      }}
    />
  )
}
