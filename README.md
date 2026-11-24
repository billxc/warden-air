# Warden Air

Zero-login Chromium autofill, passkey, and TOTP extension backed by your local **Bitwarden Desktop** app with in-place biometric unlock (macOS Touch ID / Windows Hello).

- Requires a locally installed **Bitwarden Desktop** app, **Node.js**, and the open-source Native Messaging Host in this repository.
- **Privacy Policy**: [PRIVACY.md](PRIVACY.md)
- *Independent project, not affiliated with Bitwarden Inc.*

## Setup

Supported platforms: **macOS** and **Windows** (Linux is not supported).

1. **Install and configure Bitwarden Desktop** (standard installer — not the Mac App Store / Microsoft Store sandboxed build), sign in, and in **Settings** enable:
   - **Unlock with Touch ID / Windows Hello**
   - **Allow browser integration**
   - **Allow DuckDuckGo browser integration** *(required for saving/updating logins; on Windows where this toggle may be hidden, fully quit Bitwarden Desktop from the system tray, back up `%APPDATA%\Bitwarden\data.json`, set `"global_autofillSettings_enableDuckDuckGoBrowserIntegration": true` inside it, and reopen Bitwarden Desktop)*
2. **Install Node.js** (LTS recommended; verify `node -v` works in a terminal and is on a standard install path reachable by your browser).
3. **Install the Native Messaging Host** (downloads only the `host/` files from GitHub and registers the native host for installed Chromium browsers):
   - **macOS (Terminal)** — registers Chrome, Chromium, Edge, Brave, Arc, Vivaldi, Dia, and Helium:
     ```sh
     curl -fsSL https://raw.githubusercontent.com/billxc/warden-air/main/scripts/install.sh | zsh
     ```
   - **Windows (PowerShell)** — registers Chrome, Chromium, Edge, Brave, and Vivaldi:
     ```powershell
     irm https://raw.githubusercontent.com/billxc/warden-air/main/scripts/install.ps1 | iex
     ```
4. **Connect the extension**:
   - **Chrome Web Store**: Open the Warden Air popup and click **Retry** (refresh any already-open login tabs).
   - **Local development**: See [Development](#development) below.

## Usage

| Feature | How to use | Notes |
|---|---|---|
| **Inline autofill** | Focus a login field and click **Unlock with Touch ID / Windows Hello**, or pick a matching login from the inline menu. | Works in top-level pages and iframes. |
| **Shortcut autofill** | Press `Cmd+Shift+L` (macOS) or `Ctrl+Shift+L` (Windows) on a login page. | Fills the first matching login (use inline menu or popup to pick among multiple accounts) and copies the TOTP code if configured. Rebind at `chrome://extensions/shortcuts`. |
| **Popup & Copy** | Click the toolbar icon to inspect matches, fill, or copy username/password/TOTP. | Copying a username uses already-loaded metadata; copying a password or TOTP requires an unlock. |
| **Save / Update login** | Submit a login form with a new or changed password to open the Save/Update window. | Pending capture expires after 60s; unchanged credentials do not prompt. First save may require approving the connection in Bitwarden Desktop. Choosing **Never save** permanently skips that host (no in-UI removal yet; clear extension storage to reset). |
| **Passkeys (WebAuthn)** | Use a site's **Sign in with passkey** or **Create passkey** button. | Handled via Bitwarden Desktop IPC. Conditional UI (autofill-assisted passkey) and unsupported authenticators fall back to the browser's native WebAuthn. |
| **TOTP & QR scan** | After autofilling a TOTP-enabled login, the next 2FA field offers one-click fill; or open the popup and click **Scan TOTP QR** on a 2FA setup page. | QR scan captures the visible tab locally (`BarcodeDetector` required), shows live codes, and **copies the full `otpauth://` URI (including the secret) to your clipboard** so you can paste it into Bitwarden Desktop's Authenticator Key field and save it manually. |

## Security & Behavior

- **Local-only processing**: No developer servers, analytics, or telemetry. Passwords and TOTP secrets are decrypted locally by the Native Messaging Host (which reads Bitwarden Desktop's `data.json` using the biometric-unlocked `userKey`); Passkey operations and login saves are relayed over local IPC to Bitwarden Desktop.
- **No extension login / minimal pairing**: You never enter your master password into the extension, and autofill requires no manual pairing code. Saving/updating logins uses a local Desktop handshake that may prompt for approval on first use and stores a local IPC shared key (not your vault `userKey`).
- **Single-use `userKey` auto-lock**: Once a password or TOTP secret is decrypted and delivered, the Host zeroes `userKey` in memory (while keeping short-lived TOTP handoff codes available for the next 2FA field). An unconsumed unlock (e.g., choosing among multiple accounts) auto-locks 60s after unlock, on system sleep/wake, or via **Lock**. Manual **Lock** also clears staged TOTP handoff codes, but does not clear the system clipboard or an open QR scanner window (which auto-closes after 3 minutes of inactivity).
- **Browser password-saving setting**: Once the extension receives a response from the Native Host, it sets `chrome.privacy.services.passwordSavingEnabled` to `false` to prevent duplicate browser save prompts. Disabling or uninstalling the extension restores browser control.

## Troubleshooting, Updating & Uninstall

- **Popup shows "Native host not found" / "Disconnected"**: Verify `node -v` works, re-run the Setup host install command (needed if you installed a new browser later), and ensure Bitwarden Desktop is running with **Allow browser integration** enabled.
- **Save/Update fails or times out**: Confirm Bitwarden Desktop is unlocked and **Allow DuckDuckGo browser integration** is enabled (on Windows, verify `data.json` after quitting the tray app).
- **Updating the Host**: Re-run the Setup install command. On macOS, the installer stops the old background agent automatically; on Windows, end any running `node.exe` Warden Air agent process (or reboot Windows) before clicking **Retry**.
- **Uninstalling**:
  1. Remove the Warden Air extension from your browser (restores browser password-saving control).
  2. Stop the background Host agent (macOS: terminate the `agent.mjs` process or log out; Windows: end the `agent.mjs` `node.exe` process or reboot).
  3. Delete only Warden Air's local files and native host registrations — **do not delete Bitwarden's `data.json` or vault data**:
     - **macOS**: Remove `~/.config/warden-air` and `io.github.billxc.warden_air.json` inside each browser's `~/Library/Application Support/<Browser>/NativeMessagingHosts/`.
     - **Windows**: Remove `%LOCALAPPDATA%\warden-air` and the `HKCU\Software\<Browser>\NativeMessagingHosts\io.github.billxc.warden_air` registry keys.

## Development

- **Native Host ID**: `io.github.billxc.warden_air`
- **Extension IDs**: Store `jgbhlklgdnndgheichoiibbgnincpbad` · Local unpacked dev `nphekoiaefcbmdmoknadaohgnloneeaj`

To run from a local checkout:

1. Register the local host: `./scripts/install.sh --local` (macOS) or `.\scripts\install.ps1 -Local` (Windows).
2. In `chrome://extensions` or `edge://extensions`, enable **Developer mode** -> **Load unpacked** -> select the `extension/` folder.
