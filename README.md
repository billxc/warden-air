# Warden Air

Zero-login, zero-pairing Chromium autofill extension with in-place biometric unlock (macOS Touch ID + Windows Hello).

- **Native Host ID**: `io.github.billxc.warden_air`
- **Fixed Extension ID**: `nphekoiaefcbmdmoknadaohgnloneeaj`

*Independent project, not affiliated with Bitwarden Inc.*

## Setup

1. Install standard (non-App-Store) **Bitwarden Desktop**, log in, and in **Settings** enable:
   - **Unlock with Touch ID / Windows Hello**
   - **Allow browser integration**
   - **Allow DuckDuckGo browser integration** *(required for saving new/updated logins; on Windows where this toggle is hidden in UI, set `"global_autofillSettings_enableDuckDuckGoBrowserIntegration": true` in `%APPDATA%\Bitwarden\data.json` while Bitwarden Desktop is quit)*
2. Install the Native Messaging Host directly from GitHub (requires Node.js; no local repo clone needed):
   - **macOS (Terminal)**:
     ```sh
     curl -fsSL https://raw.githubusercontent.com/billxc/warden-air/main/scripts/install.sh | zsh
     ```
   - **Windows (PowerShell)**:
     ```powershell
     irm https://raw.githubusercontent.com/billxc/warden-air/main/scripts/install.ps1 | iex
     ```
   *(For local repository development, run `./scripts/install.sh --local` or `.\scripts\install.ps1 -Local`.)*
3. In any Chromium browser (`chrome://extensions` or `edge://extensions`), turn on **Developer mode** -> **Load unpacked** -> select the `extension/` folder (if you skip step 2, the extension popup also provides a one-click install command).

## Usage & Security Model

- **Inline autofill**: Focus a login field -> click `Unlock with Touch ID / Windows Hello` (once) or pick a login from the inline menu.
- **Shortcut autofill**: Press `Cmd+Shift+L` (macOS) or `Ctrl+Shift+L` (Windows) on any login page (automatically copies 2FA TOTP to clipboard when configured).
- **Single-use auto-lock**: Every unlock is consumed immediately once a credential is autofilled or copied (`userKey` is zeroed in memory right after decryption). If unlocked to list multiple accounts, an unconsumed selection window auto-locks after 60 seconds, on system sleep/wake, or on manual `Lock`.
