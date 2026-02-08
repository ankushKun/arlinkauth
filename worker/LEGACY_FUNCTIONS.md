# WAuth - Complete Functions List

A comprehensive reference of all functions, classes, methods, types, and endpoints across the `@wauth/` packages.

---

## Table of Contents

- [WAuth - Complete Functions List](#wauth---complete-functions-list)
  - [Table of Contents](#table-of-contents)
  - [1. @wauth/sdk](#1-wauthsdk)
    - [WAuth Class](#wauth-class)
    - [WauthSigner Class](#wauthsigner-class)
    - [PasswordEncryption Class](#passwordencryption-class)
    - [HTMLSanitizer Class](#htmlsanitizer-class)
    - [Modal Functions](#modal-functions)
    - [Logger](#logger)
    - [Enums \& Types](#enums--types)
  - [2. @wauth/strategy](#2-wauthstrategy)
    - [WAuthStrategy Class](#wauthstrategy-class)
    - [Strategy Utility Functions](#strategy-utility-functions)
  - [3. Backend (Hono Server)](#3-backend-hono-server)
    - [API Endpoints](#api-endpoints)
    - [Internal Functions](#internal-functions)
  - [4. PocketBase Hooks](#4-pocketbase-hooks)
  - [Security Summary](#security-summary)

---

## 1. @wauth/sdk

### WAuth Class

The core SDK client for authentication and wallet management.

| Method                     | Signature                                                                                  | Description                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `constructor`              | `({ dev?: boolean, url?: string, backendUrl?: string })`                                   | Initializes PocketBase client, backend URL, restores auth/session state from localStorage                          |
| `connect`                  | `({ provider: WAuthProviders, scopes?: string[] }): Promise<RecordAuthResponse \| null>`   | OAuth login flow (Google, GitHub, Discord, X); creates/loads wallet, handles password modals for encrypted wallets |
| `isLoggedIn`               | `(): boolean`                                                                              | Checks if PocketBase auth store has a valid session                                                                |
| `logout`                   | `(): void`                                                                                 | Clears all auth data, session, and local storage                                                                   |
| `getActiveAddress`         | `(): Promise<string>`                                                                      | Returns the Arweave wallet address                                                                                 |
| `getActivePublicKey`       | `(): Promise<string>`                                                                      | Returns the wallet's RSA public key (base64url)                                                                    |
| `getPermissions`           | `(): Promise<PermissionType[]>`                                                            | Returns supported permissions: `ACCESS_ADDRESS`, `SIGN_TRANSACTION`                                                |
| `getWalletNames`           | `(): Promise<Record<string, string>>`                                                      | Returns `{ [address]: "WAuth" }`                                                                                   |
| `getArweaveConfig`         | `(): Promise<GatewayConfig>`                                                               | Returns Arweave gateway config (arweave.net, port 443, HTTPS)                                                      |
| `getAuthData`              | `(): RecordAuthResponse \| null`                                                           | Returns the full PocketBase auth response                                                                          |
| `getAuthToken`             | `(): string \| null`                                                                       | Returns the PocketBase auth token                                                                                  |
| `getAuthRecord`            | `(): AuthRecord \| null`                                                                   | Returns current auth user record                                                                                   |
| `getEmail`                 | `(): { email: string, verified: boolean }`                                                 | Returns user email and verification status                                                                         |
| `getUsername`              | `(): string \| null`                                                                       | Returns username from OAuth metadata                                                                               |
| `getWallet`                | `(showPasswordModal?: boolean): Promise<RecordModel \| null>`                              | Retrieves or creates user's Arweave wallet                                                                         |
| `getConnectedWallets`      | `(): Promise<RecordModel[]>`                                                               | Lists user's externally connected wallets                                                                          |
| `addConnectedWallet`       | `(address: string, pkey: string, signature: string): Promise<any>`                         | Links an external Arweave wallet via RSA-PSS signature verification                                                |
| `removeConnectedWallet`    | `(walletId: string): Promise<{ success: boolean, walletId: string }>`                      | Removes a connected external wallet                                                                                |
| `sign`                     | `(transaction: Transaction, options?: SignatureOptions): Promise<Transaction>`             | Signs an Arweave transaction via backend                                                                           |
| `signature`                | `(data: Uint8Array, algorithm?: object): Promise<Uint8Array>`                              | Signs raw data using RSA-PSS                                                                                       |
| `signAns104`               | `(dataItem: object): Promise<{ id: string, raw: ArrayBuffer }>`                            | Signs an ANS-104 data item (returns id + raw buffer)                                                               |
| `signDataItem`             | `(dataItem: object): Promise<ArrayBuffer>`                                                 | Signs a data item (returns raw ArrayBuffer)                                                                        |
| `getWauthSigner`           | `(): WauthSigner`                                                                          | Returns an arbundles-compatible signer                                                                             |
| `getAoSigner`              | `(): Function`                                                                             | Returns an AO Protocol compatible signer function                                                                  |
| `createModal`              | `(type: ModalTypes, payload: ModalPayload, callback: (result: ModalResult) => void): void` | Creates UI modals for tx confirmation or password entry                                                            |
| `onAuthDataChange`         | `(callback: Function): void`                                                               | Registers listener for auth state changes                                                                          |
| `hasSessionPassword`       | `(): boolean`                                                                              | Checks if session password is loaded in memory                                                                     |
| `isSessionPasswordLoading` | `(): boolean`                                                                              | Checks if session password is being restored                                                                       |
| `hasStoredSessionData`     | `(): boolean`                                                                              | Checks localStorage for encrypted session data                                                                     |
| `hasSessionStorageData`    | `(): boolean`                                                                              | Checks if non-expired session data exists                                                                          |
| `refreshWallet`            | `(): Promise<void>`                                                                        | Reloads wallet data from PocketBase                                                                                |
| `encryptWallet`            | `(password: string): Promise<boolean>`                                                     | Encrypts an unencrypted wallet with a master password                                                              |
| `isWalletEncrypted`        | `(): boolean`                                                                              | Checks if the wallet is password-encrypted                                                                         |
| `pocketbase`               | `(): PocketBase`                                                                           | Returns the underlying PocketBase client instance                                                                  |

**Static properties:**
- `WAuth.version: string` -- SDK version string

---

### WauthSigner Class

Arbundles-compatible signer for ANS-104 data items.

| Method/Property   | Signature                                                                           | Description                          |
| ----------------- | ----------------------------------------------------------------------------------- | ------------------------------------ |
| `constructor`     | `(wauth: WAuth)`                                                                    | Creates signer from a WAuth instance |
| `publicKey`       | `Buffer`                                                                            | RSA public key buffer                |
| `ownerLength`     | `512`                                                                               | Owner length constant                |
| `signatureLength` | `512`                                                                               | Signature length constant            |
| `signatureType`   | `1`                                                                                 | Arweave signature type               |
| `setPublicKey`    | `(): Promise<void>`                                                                 | Loads public key from wallet         |
| `sign`            | `(message: Uint8Array): Promise<Uint8Array>`                                        | Signs a message                      |
| `verify`          | `static (pk: Buffer, message: Uint8Array, signature: Uint8Array): Promise<boolean>` | Verifies an RSA-PSS signature        |

---

### PasswordEncryption Class

Handles RSA-OAEP encrypted password transmission to the backend.

| Method                | Signature                                                        | Description                                                         |
| --------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------- |
| `getBackendPublicKey` | `static (backendUrl: string): Promise<CryptoKey>`                | Fetches and caches backend's RSA public key                         |
| `encryptPassword`     | `static (password: string, backendUrl: string): Promise<string>` | Encrypts password with nonce + timestamp for anti-replay protection |

---

### HTMLSanitizer Class

XSS-safe HTML handling utilities for modal content.

| Method             | Signature                                                                   | Description                                     |
| ------------------ | --------------------------------------------------------------------------- | ----------------------------------------------- |
| `escapeHTML`       | `static (text: string): string`                                             | Escapes HTML entities (`<`, `>`, `&`, `"`, `'`) |
| `sanitizeHTML`     | `static (text: string, allowedTags?: string[]): string`                     | Sanitizes HTML with a tag whitelist             |
| `safeSetInnerHTML` | `static (element: HTMLElement, html: string, allowedTags?: string[]): void` | Safe innerHTML setter                           |
| `createSafeLink`   | `static (href: string, text: string, target?: string): HTMLAnchorElement`   | Creates URL-validated anchor elements           |

---

### Modal Functions

DOM-based modal UI (no framework dependency).

| Function                      | Signature                                                                       | Description                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `createModalContainer`        | `(): HTMLDivElement`                                                            | Creates full-screen overlay with backdrop blur and animation                    |
| `createModal`                 | `(type: ModalTypes, payload: ModalPayload, onResult: Function): HTMLDivElement` | Factory dispatching to the appropriate modal type                               |
| `createConfirmTxModal`        | `(payload: ModalPayload, onResult: Function): HTMLDivElement`                   | Transaction confirmation modal with token details, amount, tags, approve/cancel |
| `createPasswordNewModal`      | `(payload: ModalPayload, onResult: Function): HTMLDivElement`                   | New password creation modal with strength meter, encrypt/skip options           |
| `createPasswordExistingModal` | `(payload: ModalPayload, onResult: Function): HTMLDivElement`                   | Existing password entry modal with unlock/cancel                                |

---

### Logger

Singleton logger with colorful console output.

| Function/Method           | Signature                                                                                 | Description                                                |
| ------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `WAuthLogger.getInstance` | `(): WAuthLogger`                                                                         | Singleton accessor                                         |
| `setLogLevel`             | `(level: LogLevel): void`                                                                 | Set minimum log level                                      |
| `debug`                   | `(component: string, message: string, data?: any): void`                                  | Debug-level log                                            |
| `info`                    | `(component: string, message: string, data?: any): void`                                  | Info-level log                                             |
| `warn`                    | `(component: string, message: string, data?: any): void`                                  | Warning-level log                                          |
| `error`                   | `(component: string, message: string, error?: any): void`                                 | Error-level log                                            |
| `authStart`               | `(operation: string, provider?: string, input?: any): void`                               | Log auth operation start                                   |
| `authSuccess`             | `(operation: string, result?: any, duration?: number): void`                              | Log auth success                                           |
| `authError`               | `(operation: string, error: any, duration?: number): void`                                | Log auth failure                                           |
| `walletOperation`         | `(operation: string, details?: any): void`                                                | Log wallet operations                                      |
| `sessionUpdate`           | `(action: string, details?: any): void`                                                   | Log session changes                                        |
| `passwordOperation`       | `(operation: string, success?: boolean, attempt?: number): void`                          | Log password events                                        |
| `backendRequest`          | `(method: string, endpoint: string, status?: number): void`                               | Log API calls                                              |
| `initialization`          | `(message: string, data?: any): void`                                                     | Log SDK initialization events                              |
| `simple`                  | `(level: LogLevel, message: string, data?: any): void`                                    | Generic styled log                                         |
| `measureWAuthTime`        | `<T>(fn: () => Promise<T>): Promise<{ result: T, duration: number }>`                     | Measure async function execution time                      |
| `loggedWAuthOperation`    | `<T>(operation: string, input: any, fn: () => Promise<T>, provider?: string): Promise<T>` | Wrap operations with automatic start/success/error logging |

---

### Enums & Types

**`WAuthProviders`**
| Value     | String      |
| --------- | ----------- |
| `Google`  | `"google"`  |
| `Github`  | `"github"`  |
| `Discord` | `"discord"` |
| `X`       | `"twitter"` |

**`WalletActions`**
| Value            | Description                 |
| ---------------- | --------------------------- |
| `SIGN`           | Sign an Arweave transaction |
| `ENCRYPT`        | Encrypt data (stub)         |
| `DECRYPT`        | Decrypt data (stub)         |
| `DISPATCH`       | Dispatch transaction (stub) |
| `SIGN_DATA_ITEM` | Sign an ANS-104 data item   |
| `SIGNATURE`      | Sign raw data               |

**`LogLevel`**
| Value   | Level |
| ------- | ----- |
| `DEBUG` | `0`   |
| `INFO`  | `1`   |
| `WARN`  | `2`   |
| `ERROR` | `3`   |
| `OFF`   | `4`   |

**Types:**
- `ModalTypes` -- `"confirm-tx" | "password-new" | "password-existing"`
- `ModalPayload` -- `{ transaction?: Transaction, dataItem?: ArConnectDataItem, tokenDetails?: any, errorMessage?: string }`
- `ModalResult` -- `{ proceed: boolean, password?: string, skipPassword?: boolean }`

---

## 2. @wauth/strategy

### WAuthStrategy Class

Arweave Wallet Kit strategy adapter wrapping the WAuth SDK.

| Method/Property            | Signature                                                            | Description                                            |
| -------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------ |
| `constructor`              | `({ provider: WAuthProviders, scopes?: string[] })`                  | Creates strategy for a specific OAuth provider         |
| `id`                       | `string`                                                             | `"wauth-{provider}"`                                   |
| `name`                     | `string`                                                             | Capitalized provider name                              |
| `description`              | `string`                                                             | `"WAuth"`                                              |
| `theme`                    | `string`                                                             | `"25,25,25"` (dark theme)                              |
| `logo`                     | `string`                                                             | Arweave TX ID for provider logo                        |
| `url`                      | `string`                                                             | `"https://subspace.ar.io"`                             |
| `connect`                  | `(permissions?: PermissionType[]): Promise<void>`                    | OAuth connect flow                                     |
| `reconnect`                | `(): Promise<any>`                                                   | Re-authenticate existing session                       |
| `disconnect`               | `(): Promise<void>`                                                  | Logout and clear session                               |
| `getActiveAddress`         | `(): Promise<string>`                                                | Get active Arweave address                             |
| `getAllAddresses`          | `(): Promise<string[]>`                                              | Get all wallet addresses                               |
| `getActivePublicKey`       | `(): Promise<string>`                                                | Get active wallet public key                           |
| `sign`                     | `(transaction: Transaction, options?: object): Promise<Transaction>` | Sign an Arweave transaction                            |
| `signDataItem`             | `(dataItem: object): Promise<ArrayBuffer>`                           | Sign a data item                                       |
| `signAns104`               | `(dataItem: object): Promise<{ id: string, raw: ArrayBuffer }>`      | Sign ANS-104 data item                                 |
| `signature`                | `(data: Uint8Array, algorithm: object): Promise<Uint8Array>`         | Sign raw data                                          |
| `getPermissions`           | `(): Promise<PermissionType[]>`                                      | Get supported permissions                              |
| `getWalletNames`           | `(): Promise<Record<string, string>>`                                | Get wallet names map                                   |
| `encrypt`                  | `(data: Uint8Array, options: object): Promise<Uint8Array>`           | Not implemented (throws)                               |
| `decrypt`                  | `(data: Uint8Array, options: object): Promise<Uint8Array>`           | Not implemented (throws)                               |
| `getArweaveConfig`         | `(): Promise<GatewayConfig>`                                         | Get Arweave gateway config                             |
| `isAvailable`              | `(): Promise<boolean>`                                               | Always returns `true`                                  |
| `dispatch`                 | `(transaction: Transaction): Promise<DispatchResult>`                | Not implemented (throws)                               |
| `addConnectedWallet`       | `(wallet: ArweaveWallet): Promise<any>`                              | Connect an external wallet with signature verification |
| `removeConnectedWallet`    | `(walletId: string): Promise<any>`                                   | Remove a connected wallet                              |
| `getConnectedWallets`      | `(): Promise<any[]>`                                                 | List connected wallets                                 |
| `getAoSigner`              | `(): Function`                                                       | Get AO Protocol compatible signer                      |
| `getEmail`                 | `(): { email: string, verified: boolean }`                           | Get user email and verification status                 |
| `getUsername`              | `(): string \| null`                                                 | Get OAuth username                                     |
| `encryptWallet`            | `(password: string): Promise<boolean>`                               | Encrypt unencrypted wallet                             |
| `isWalletEncrypted`        | `(): boolean`                                                        | Check wallet encryption status                         |
| `onAuthDataChange`         | `(callback: Function): void`                                         | Register auth state listener                           |
| `getAuthData`              | `(): any`                                                            | Get current auth data                                  |
| `addAddressEvent`          | `(listener: Function): Function`                                     | Register address change listener (returns unsubscribe) |
| `removeAddressEvent`       | `(listener: Function): void`                                         | Remove address change listener                         |
| `getWindowWalletInterface` | `(): object`                                                         | Returns `window.arweaveWallet`-compatible interface    |

### Strategy Utility Functions

| Function                 | Signature                                                           | Description                                                                         |
| ------------------------ | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `fixConnection`          | `(address: string, connected: boolean, disconnect: Function): void` | Detects stale connection state and forces disconnect when wallet session is invalid |
| `getStrategy`            | `(provider: WAuthProviders): WAuthStrategy`                         | Returns singleton strategy instance for a provider (demo helper)                    |
| `getActiveWAuthProvider` | `(): WAuthProviders \| null`                                        | Reads active provider from localStorage (demo helper)                               |

**Re-exports:** `WAuthProviders` from `@wauth/sdk`

---

## 3. Backend (Hono Server)

### API Endpoints

| Method | Endpoint              | Auth                                                                       | Description                                                                                                  |
| ------ | --------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `GET`  | `/`                   | None                                                                       | Health check -- returns `{ message, timestamp }`                                                             |
| `GET`  | `/public-key`         | None                                                                       | Returns server's RSA-OAEP public key (JWK format) for password encryption                                    |
| `GET`  | `/jwk`                | Headers: `encrypted-password`, `encrypted-confirm-password`                | Generates new Arweave JWK encrypted with user password. Returns `{ encryptedJWK, salt, address, publicKey }` |
| `GET`  | `/jwk-skip-password`  | None                                                                       | Generates unencrypted Arweave JWK. Returns `{ regular_jwk, address, publicKey }`                             |
| `POST` | `/verify-password`    | Bearer token + `encrypted-password` header                                 | Verifies password can decrypt user's encrypted JWK. Returns `{ valid: boolean }`                             |
| `POST` | `/connect-wallet`     | Bearer token + JSON body                                                   | Connects external wallet via RSA-PSS signature verification. Body: `{ address, pkey, signature }`            |
| `GET`  | `/check-bot/:guildId` | None                                                                       | Checks if Discord bot is present in a guild                                                                  |
| `POST` | `/encrypt-wallet`     | Bearer token + `encrypted-password` + `encrypted-confirm-password` headers | Encrypts an existing unencrypted wallet with a password                                                      |
| `POST` | `/wallet-action`      | Bearer token                                                               | Executes wallet operations. Body: `{ action, payload, encryptedPassword? }`                                  |

**Wallet Actions (via `/wallet-action`):**

| Action           | Payload                                        | Description                                      |
| ---------------- | ---------------------------------------------- | ------------------------------------------------ |
| `SIGN`           | `{ transaction: object }`                      | Signs an Arweave transaction with the user's JWK |
| `SIGN_DATA_ITEM` | `{ dataItem: { data, tags, target, anchor } }` | Creates and signs an ANS-104 data item           |
| `SIGNATURE`      | `{ data: number[] }`                           | Signs raw data bytes with ArweaveSigner          |
| `ENCRYPT`        | --                                             | Not implemented (stub)                           |
| `DECRYPT`        | --                                             | Not implemented (stub)                           |
| `DISPATCH`       | --                                             | Not implemented (stub)                           |

### Internal Functions

| Function               | Signature                                                             | Description                                                                                     |
| ---------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `initializeServerKeys` | `(): Promise<void>`                                                   | Generates 2048-bit RSA-OAEP key pair on server boot                                             |
| `decryptPassword`      | `(encryptedData: string): Promise<{ password, nonce, timestamp }>`    | Decrypts RSA-OAEP encrypted password, validates 1-min timestamp window, checks nonce uniqueness |
| `encryptJWK`           | `(jwk: object, password: string): Promise<{ encryptedJWK, salt }>`    | PBKDF2 (100K iterations, SHA-256) + AES-256-GCM encryption; separates public key `n`            |
| `decryptJWK`           | `(encryptedJWK, salt, password, publicKey): Promise<JWK>`             | Reverses encryptJWK; re-attaches public key `n`                                                 |
| `validateSignature`    | `(address, publicKeyString, signatureBase64String): Promise<boolean>` | Verifies RSA-PSS signature with SHA-256                                                         |
| `cleanupExpiredNonces` | `(): void`                                                            | Periodic cleanup of expired nonces (runs every 1 minute)                                        |

---

## 4. PocketBase Hooks

Server-side lifecycle hooks running inside PocketBase.

| Hook                            | Collection          | Description                                                                                                                       |
| ------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `onBootstrap`                   | --                  | Logs PocketBase initialization                                                                                                    |
| `onRecordAuthWithOAuth2Request` | --                  | Pass-through (no custom logic)                                                                                                    |
| `onRecordCreateRequest`         | `connected_wallets` | Auto-sets `user` field from authenticated user                                                                                    |
| `onRecordCreateRequest`         | `wallets`           | Auto-sets `user` field; calls backend `/jwk` or `/jwk-skip-password` to generate wallet keys; stores encrypted or unencrypted JWK |
| `onRecordAfterCreateSuccess`    | `wallets`           | Pass-through (no custom logic)                                                                                                    |
| `onRecordEnrich`                | `wallets`           | Hides `encrypted_jwk` and `salt` fields from API responses (security)                                                             |

**Utility:**

| Function     | Signature                   | Description                                                 |
| ------------ | --------------------------- | ----------------------------------------------------------- |
| `bodyToJson` | `(body: ByteArray): object` | Converts PocketBase HTTP response byte array to parsed JSON |

---

## Security Summary

| Feature                  | Implementation                                              |
| ------------------------ | ----------------------------------------------------------- |
| Password transmission    | RSA-OAEP encryption (2048-bit)                              |
| Anti-replay protection   | Nonce + timestamp validation (1-min window)                 |
| JWK storage encryption   | PBKDF2 (100K iterations, SHA-256) + AES-256-GCM             |
| Session password caching | AES-256-GCM via Web Crypto API (3-hour expiry)              |
| Modal XSS prevention     | HTML sanitization with tag whitelist                        |
| API field protection     | `encrypted_jwk` and `salt` hidden from PocketBase responses |
| External wallet linking  | RSA-PSS signature verification                              |
| Rate limiting            | Exponential backoff on password attempts                    |
