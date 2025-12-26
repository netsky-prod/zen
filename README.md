# Zen VPN

Simple VLESS VPN client for Linux and Windows using sing-box.

## Features

- VLESS protocol support with WebSocket transport
- TUN mode (routes all traffic through VPN)
- Auto-download sing-box engine
- System tray support
- Dark/Light theme
- Ping measurement

## Installation

### Linux

Download `.deb` or `.rpm` from [Releases](../../releases):

```bash
# Debian/Ubuntu
sudo dpkg -i Zen_*_amd64.deb

# Fedora/RHEL
sudo dnf install Zen-*.x86_64.rpm
```

### Windows

Download `.exe` installer from [Releases](../../releases) and run it.

## Usage

1. Launch Zen from applications menu
2. Click "Download Engine" on first run
3. Paste your VLESS link and click "Add"
4. Select a profile and click "Connect"
5. Enter password when prompted (root/admin required for TUN mode)

### Tray on GNOME
GNOME скрывает иконки трея без поддержки AppIndicator. Установите `libayatana-appindicator3` (или аналогичный пакет дистрибутива) и включите расширение “AppIndicator and KStatusNotifierItem Support”, чтобы иконка Zen появилась в трее и окно можно было сворачивать.

## CI/CD (GitLab)
- Проект должен быть public, чтобы обновления качались без токенов.
- В `.gitlab-ci.yml` настроены сборки:
  - Linux: deb + rpm (job `build-linux`)
  - Windows: nsis `.exe` (job `build-windows`, нужен Windows runner с тегом `windows`)
  - `manifest` генерирует `manifest.json` с sha256 и ссылками для апдейта.
  - `release` публикует GitLab Release по тегу `vX.Y.Z` (требует `GITLAB_TOKEN` в CI/CD variables).
- Клиентское автообновление ожидает `manifest.json` и ассеты в GitLab Releases по URL:
  `https://gitlab.com/<namespace>/<project>/-/releases/<tag>/downloads/<file>`

## Building from source

Requirements:
- Node.js 18+
- Rust 1.70+
- Linux: `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev`

```bash
npm install
npm run tauri build
```

## License

MIT
