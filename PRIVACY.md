# Privacy Policy — Warden Air

**Last updated:** 2026-11-25

Warden Air is a local-first browser extension that works with a separate, user-installed open-source Native Messaging Host and your locally installed **Bitwarden Desktop** application.

## Data Handled

All processing happens locally on your device for the single purpose of password, passkey, and TOTP authentication with Bitwarden Desktop:

| Data | How it is used |
|---|---|
| **Page & frame URLs / origins** | Read by content scripts (`http://*/*` and `https://*/*` for inline autofill and login save detection; `https://*/*` and `http://localhost/*` for WebAuthn passkey bridging, including iframes) to match credentials and passkeys for the active site. |
| **Vault data, credentials & passkeys** | After Touch ID / Windows Hello unlock, the local Native Messaging Host receives the unlocked `userKey`, reads Bitwarden Desktop's local `data.json`, builds an in-memory index of matching URIs, item names, and passkey metadata, and decrypts requested usernames, passwords, and TOTP secrets locally. Passkey registration/assertion and login saves are forwarded over local IPC to Bitwarden Desktop. |
| **Submitted login forms** | When you submit a new or modified login form (or click a form submit button), the entered username and password are held in memory for up to 60 seconds so you can choose to save or update them in Bitwarden Desktop. |
| **Visible tab screenshot & TOTP secret (QR scan)** | Only when you click **Scan TOTP QR** or **Scan Again**, the extension captures a PNG screenshot of the active tab's visible area (`chrome.tabs.captureVisibleTab`) and decodes the QR code locally in the browser (`BarcodeDetector`). The decoded `otpauth://` URI (containing the TOTP secret) is held in the scanner window to generate live verification codes, staged briefly with the local Host for autofill handoff, and automatically copied to your system clipboard so you can save it into Bitwarden Desktop. |
| **Clipboard** | Writing a username, password, TOTP code, or scanned `otpauth://` URI to the system clipboard when you trigger Copy, TOTP autofill, or Scan TOTP QR. |
| **Site exclusions (`chrome.storage.local`)** | Hosts where you choose **Never save** are stored locally in `chrome.storage.local`. |
| **Native Host local state** | The Native Messaging Host stores a local application identifier and a Bitwarden Desktop IPC shared key (not your vault `userKey` or master password) in `~/.config/warden-air/session.json` (macOS) or `%LOCALAPPDATA%\warden-air\session.json` (Windows). |

## Data Sharing & Network Transmission

- **No developer servers or telemetry**: Warden Air does not collect analytics, usage telemetry, or crash reports, and never sends your credentials, screenshots, or browsing history to any server operated by the developer.
- **Website authentication & Bitwarden sync**: Decrypted credentials, TOTP codes, and passkey assertions are supplied only to the website you are authenticating with. If you save or update a login, Bitwarden Desktop handles vault syncing according to your own Bitwarden account settings.
- **External links**: Clicking the setup documentation or issue links opens GitHub in a new tab.

## Retention & Removal

- **In-memory data**: The Host's `userKey` is zeroed immediately after decrypting a requested secret (or 60 seconds after unlock if not consumed / on system sleep / on manual **Lock**). Pending login saves expire after 60s; TOTP handoff codes are short-lived and cleared on manual **Lock**; the QR scanner window closes automatically after 3 minutes of inactivity (reset on interaction).
- **Clipboard**: Values copied to your system clipboard (including scanned `otpauth://` URIs) are not automatically cleared by the extension.
- **Persistent local data**: Removing the extension clears `chrome.storage.local`. To remove the Native Messaging Host and its local IPC shared key, follow the uninstall steps in `README.md`.

## Browser Settings

Once the extension receives a response from the local Native Messaging Host, it disables the browser's built-in password-saving prompt (`chrome.privacy.services.passwordSavingEnabled = false`) to avoid duplicate save prompts. Disabling or uninstalling the extension restores browser control of this setting.

## Contact

For questions or privacy inquiries, please open an issue at:
https://github.com/billxc/warden-air/issues
