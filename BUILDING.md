# Building from source

Most people should download the installers from the [Releases](../../releases) page. This guide is for running the app from source or building your own installers.

## Requirements

| Tool | Version |
|---|---|
| Node.js | 22 or later (24 recommended) |
| npm | Comes with Node.js |
| macOS | Needed to build the Mac `.dmg` |
| Windows or macOS | Either can build the Windows `.exe` |

## 1. Install the dependencies

```bash
git clone https://github.com/Johnmat1975/ops-portal.git
cd ops-portal
npm install
```

## 2. Run it

```bash
npm start
```

The app opens empty. Enter your Liongard instance (the part before `.app.liongard.com`) and a **read-only** access key and secret, then pick a client.

- Runs from source keep their settings in `~/Library/Application Support/liongard-ops-portal` on macOS, or `%APPDATA%\liongard-ops-portal` on Windows.
- Installed copies use a separate "Liongard Ops Portal" folder.
- The access key is encrypted with the operating system keychain (Electron `safeStorage`), and only the app's main process ever sees it.

## 3. Build the installers

```bash
npm run dist:mac   # dist/Liongard Ops Portal-<version>-universal.dmg (Apple Silicon and Intel)
npm run dist:win   # dist/Liongard Ops Portal Setup <version>.exe (64-bit)
npm run dist       # both
```

The version comes from `"version"` in `package.json`.

The builds are unsigned, so macOS Gatekeeper and Windows SmartScreen warn the first time the app opens. To sign your own builds, add a Developer ID certificate and notarisation settings under `build.mac`, and a code-signing certificate under `build.win` (see the [electron-builder documentation](https://www.electron.build/code-signing)). Never commit certificates, passwords or keys.

The builds set Electron fuses: the app binary can't run as plain Node, ignores `NODE_OPTIONS` and `--inspect`, only loads its own `app.asar`, and refuses an `app.asar` that has been changed.

## How the code is organised

| Path | What it is |
|---|---|
| `src/main/main.js` | The Electron main process: settings, encrypted key storage, caching, and the bridge to the pages |
| `src/main/api.js` | The Liongard API client |
| `src/main/panels/` | One file per page: what it reads from Liongard (`collect`) and the rules that turn it into the page (`compute`) |
| `src/main/frameworks/` | The control lists for each compliance framework |
| `src/main/catalog.js` | Shared reference data: tool categories, Windows support dates, MITRE ATT&CK v20.0 techniques |
| `src/main/stack*.js`, `metric-signals.js` | How the app discovers your inspectors and uses Liongard's own metrics |
| `src/renderer/` | The pages: HTML, CSS, the shared top bar and side menu, and one view per page in `views/` |

## How data flows

| Step | Liongard API call |
|---|---|
| Clients for the picker | `GET /api/v1/environments` |
| Launchpoints, inspectors, schedules | `GET /api/v1/launchpoints` |
| Last attempt for every launchpoint | `GET /api/v1/timeline` |
| The fields each page needs | `POST /api/v2/dataprints/evaluate/{systemDetailId}`, using the JMESPath in each `src/main/panels/*.js` |
| Liongard's own metric results | `POST /api/v2/metrics/evaluate/systems` |

Results are cached per client on your computer and only pulled again when you click **Refresh**.
