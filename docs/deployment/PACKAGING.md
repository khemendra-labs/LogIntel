# LogIntel — Debian Packaging & Installation Guide

LogIntel produces a Linux `.deb` package (`logintel_0.1.0_amd64.deb`).

## 1. Packaging Architecture

The Debian package deploys:
- `/usr/bin/logintel`: Compiled Tauri application executable
- `/usr/share/applications/logintel.desktop`: Desktop entry for application launcher
- `/usr/share/icons/hicolor/128x128/apps/logintel.png`: Application icon
- `/usr/lib/logintel/engine`: Engine Python modules and runtime environment

## 2. Generating the Debian Package

Run the packaging script from the repository root:
```bash
./scripts/build_deb.sh
```

Or using Tauri build toolchain directly:
```bash
cd apps/desktop
npm run tauri build -- --bundles deb
```

Generated artifact will be located in:
`apps/desktop/src-tauri/target/release/bundle/deb/logintel_0.1.0_amd64.deb`

## 3. Installation Experience

Install the package using `dpkg` or `apt`:
```bash
sudo dpkg -i logintel_0.1.0_amd64.deb
# If dependencies need resolving:
sudo apt-get install -f
```

Then launch LogIntel from the application menu:
```text
Applications → System → LogIntel
```
Or directly from the terminal as an unprivileged user:
```bash
logintel
```

No manual background daemon or python command is required. The desktop application manages the local engine process automatically.

## 4. Uninstallation
```bash
sudo apt-get remove logintel
```
