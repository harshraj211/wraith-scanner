# Wraith Desktop Foundation

This folder contains the first packaging foundation for a desktop Wraith app.

It does not change Wraith into a closed-source product by itself. Python and
JavaScript desktop bundles can be reverse engineered, so sensitive secrets and
private offensive logic must stay server-side or behind licensed update channels
in a future commercial architecture.

## Current Model

- `desktop/wraith_desktop.py` starts the Flask API with `api_server.py`.
- It serves the compiled React app from `scanner-terminal/build`.
- It opens the local UI in the user's default browser.
- Manual mode can then launch the controlled Wraith browser through the local proxy.

## Build

From the repository root on Windows:

```powershell
.\scripts\build_desktop.ps1
```

The script:

1. Runs `npm install` and `npm run build` inside `scanner-terminal`.
2. Installs Python runtime requirements.
3. Installs `desktop/requirements-desktop.txt`.
4. Runs PyInstaller with `desktop/pyinstaller/wraith_desktop.spec`.

The bundle is written to:

```text
dist\WraithDesktop
```

## Run Without Packaging

```powershell
cd scanner-terminal
npm run build
cd ..
python -m desktop.wraith_desktop
```

Options:

```text
--ui-port 3000
--api-port 5001
--no-browser
```

## Next Desktop Steps

- Add code signing for Windows installers.
- Add a real installer layer such as WiX, Inno Setup, or MSIX.
- Add update channels for Wraith modules, Nuclei assets, and UI builds.
- Add a license/activation gate if source distribution becomes a commercial concern.
- Keep intrusive modules gated by policy and operator acknowledgement.
