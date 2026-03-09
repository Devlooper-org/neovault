# NeoVault

NeoVault is a fast, zero-knowledge password manager. It's built to keep your data local and your server blind to your passwords.

## Features

- **Local encryption**: your passwords never leave your browser. everything is encrypted before it hits the server.
- **Dual passwords**: one to log in, another to unlock your vault.
- **TOTP**: built-in 2FA support for every credential.
- **Session unlock**: unlock once and stay logged in until you close the tab.
- **Simple UI**: clean dark theme that works on your phone.
- **Secure**: uses AES-256-GCM and proper key derivation.

## Setup

1. **Clone it**:
   ```bash
   git clone https://github.com/jigarvarma2k20/neovault.git
   cd neovault
   ```

2. **Config**:
   ```bash
   cp .env.sample .env
   ```
   Open `.env` and add your database URL. 
   
   For the `JWT_SECRET`, run this to get a random string:
   ```bash
   openssl rand -base64 32
   ```

3. **Get deps**:
   ```bash
   go mod tidy
   npm install
   ```

4. **Assets**:
   ```bash
   npm run build:css
   ```

5. **Run**:
   ```bash
   go run .
   ```

## Security

- users are hashed with `bcrypt`.
- the vault is never stored on the server. a hash is used only to verify your vault session.
- each credential gets its own key derived via HKDF (SHA-256).
