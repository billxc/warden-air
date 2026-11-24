# Privacy Policy — Warden Air

**Last updated:** 2026-11-24

Warden Air is a local-first browser extension that bridges Chromium browsers with your locally installed **Bitwarden Desktop** application via a separate open-source Native Messaging Host.

## Data Processed

To provide autofill, passkey authentication, and login saving, the extension processes:

- **Active page URL / origin**: Used to match credentials and passkeys for the current site.
- **Credentials & Passkeys**: Decrypted locally via your Bitwarden Desktop app (after Touch ID / Windows Hello verification) and filled into the active page on request. When you submit a new or changed login form, the submitted username and password are held temporarily in memory so you can choose to save or update them in Bitwarden Desktop.
- **Clipboard**: When autofilling a login with TOTP enabled or clicking Copy, the requested value (username, password, or TOTP code) is written to the system clipboard.
- **Site Exclusions (`chrome.storage.local`)**: Sites where you choose "Never save" are stored locally in `chrome.storage.local`.

## Data Sharing & Network Transmission

- **No telemetry, analytics, or external servers**: The extension does not collect analytics, tracking data, or send your credentials to any server operated by the developer.
- **Local-only communication**: All credential and passkey operations happen locally between the extension, the user-installed Native Messaging Host, and Bitwarden Desktop on your device. If you choose to save or update a login, Bitwarden Desktop handles syncing according to your own Bitwarden account configuration.

## Browser Settings

Once connected to the local Native Messaging Host, Warden Air disables the browser's built-in password-saving prompt (`chrome.privacy.services.passwordSavingEnabled`) to avoid duplicate save prompts. Disabling or uninstalling the extension restores browser control of this setting.

## Contact

For questions or issues, please open an issue at:
https://github.com/billxc/warden-air/issues
