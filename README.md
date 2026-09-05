# ProcessV

ProcessV is a tiny, dependency-free macOS menu-bar utility for seeing which local TCP ports are listening and which processes own them.

It also recognizes servers launched from Codex tasks. Those rows receive a ChatGPT mark and can jump directly back to the originating Codex task.

![macOS 26](https://img.shields.io/badge/macOS-26%2B-black)
![Swift](https://img.shields.io/badge/Swift-native-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

## What it does

- Shows user-relevant listening TCP ports in the menu bar, newest process first.
- Marks servers launched by Codex without separating manually launched servers.
- Opens a server at `http://127.0.0.1:<port>`.
- Opens the originating Codex task when one can be identified.
- Sends a graceful `SIGTERM` to stoppable processes.
- Supports Mail-style gestures: swipe left to stop immediately, swipe right to open Codex.
- Refreshes whenever the popover opens and closes when you click elsewhere.
- Uses macOS 26 Liquid Glass and adapts to light and dark appearance.
- Runs natively on Apple silicon and Intel Macs.

System services and protected app processes are intentionally hidden or protected from termination.

## Requirements

- macOS 26 or later.
- ChatGPT with Codex installed for Codex ownership badges and task links. Port monitoring works without it.

## Install

The universal `ProcessV.app` is committed directly in this repository. For the easiest download:

1. Download `ProcessV.zip` from the latest GitHub release.
2. Unzip it and move `ProcessV.app` to Applications.
3. Open ProcessV. Its server-rack icon appears in the menu bar.

The downloadable build is ad-hoc signed because this project does not currently have an Apple Developer ID certificate. If Gatekeeper blocks the first launch, Control-click `ProcessV.app`, choose **Open**, then confirm. You can also allow it in **System Settings → Privacy & Security**. Subsequent launches work normally.

## Build from source

The complete application is implemented in one Swift source file and uses only Apple frameworks and Darwin APIs. Xcode 26 or its matching command-line tools are required.

```sh
chmod +x build.sh
./build.sh
open dist/ProcessV.app
```

The script produces a universal `arm64` + `x86_64` app at `dist/ProcessV.app`.

## How Codex detection works

ProcessV scans local listening sockets using macOS process APIs. For each listener, it checks the process and a limited ancestor chain for `CODEX_THREAD_ID` and `CODEX_SESSION_ID`. When a thread ID is present, ProcessV can open `codex://threads/<id>`.

This is best-effort. macOS may prevent inspection of some processes, and a server detached from its original process tree may not retain Codex metadata.

## Privacy

ProcessV is local-only:

- No analytics or telemetry.
- No outbound network requests.
- No saved history or preferences.
- No server, process, task, or session data is written to disk.

Task and session identifiers are read only from running local processes when the menu is refreshed. The optional `--scan-once` diagnostic prints current results to the terminal that invoked it.

## Safety

The normal stop button asks for confirmation. A committed left swipe intentionally skips confirmation. Both send `SIGTERM`, not `SIGKILL`, and ProcessV verifies process identity before signaling to reduce PID-reuse risk.

## Trademark

ProcessV is an independent project and is not affiliated with or endorsed by OpenAI. ChatGPT, Codex, and the ChatGPT logo are trademarks of OpenAI. The mark is used only to identify locally running processes associated with Codex.

## License

MIT. See [LICENSE](LICENSE).
