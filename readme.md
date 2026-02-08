# Arlink Auth

OAuth authentication with automatic Arweave wallet generation. Users sign in with GitHub or Google, and get a server-side Arweave wallet they can use to sign transactions and upload data.

## Features

- GitHub & Google OAuth login
- Automatic Arweave wallet creation per user
- Sign Arweave transactions and data items
- Upload to Arweave via Turbo bundler
- Custom OAuth scopes support
- Works from any domain (CORS enabled)
- React hooks included

## Project Structure

```
arlinkauth/
├── worker/     # Cloudflare Worker backend (OAuth, wallet storage, signing)
├── sdk/        # TypeScript SDK (npm: arlinkauth)
└── frontend/   # Demo app
```

## Installation

```bash
npm install arlinkauth
# or
bun add arlinkauth
```

## Quick Start

### Basic Usage

```typescript
import { createWauthClient } from 'arlinkauth';

const client = createWauthClient({
  apiUrl: 'https://your-worker.workers.dev'
});

// Initialize (checks for existing session)
await client.init();

// Login with GitHub
const result = await client.loginWithGithub();
if (result.success) {
  console.log('Logged in as:', result.user.name);
  console.log('Arweave address:', result.user.arweave_address);
  console.log('GitHub token:', result.user.github_access_token);
}

// Login with Google
await client.loginWithGoogle();

// Check auth state
client.isAuthenticated(); // boolean
client.getState();        // { user, token, isLoading, isAuthenticated }

// Logout
client.logout();
```

### Custom GitHub Scopes

Request additional GitHub permissions beyond the defaults (`read:user`, `user:email`):

```typescript
const result = await client.loginWithGithub({
  scopes: ['repo', 'read:org', 'gist']
});

if (result.success) {
  // Token now has access to repos, orgs, and gists
  const token = result.user.github_access_token;
  
  // Use token with GitHub API
  const repos = await fetch('https://api.github.com/user/repos', {
    headers: { Authorization: `Bearer ${token}` }
  });
}
```

### Sign Data Items

Sign ANS-104 data items for Arweave bundlers:

```typescript
const { id, raw } = await client.signDataItem({
  data: 'Hello Arweave!',
  tags: [
    { name: 'Content-Type', value: 'text/plain' },
    { name: 'App-Name', value: 'My App' }
  ]
});

console.log('Data item ID:', id);
// raw contains the signed bytes to submit to a bundler
```

### Upload to Arweave

Sign and upload in one call via Turbo bundler:

```typescript
const result = await client.dispatch({
  data: 'Hello Arweave!',
  tags: [
    { name: 'Content-Type', value: 'text/plain' }
  ]
});

console.log('Transaction ID:', result.id);
console.log('View at:', `https://arweave.net/${result.id}`);
```

### Raw Signatures

Sign arbitrary data:

```typescript
const { signature } = await client.signature({
  data: 'Message to sign'
});

console.log('Signature bytes:', signature); // number[]
```

## React Integration

```tsx
import { AuthProvider, useAuth } from 'arlinkauth/react';

function App() {
  return (
    <AuthProvider apiUrl="https://your-worker.workers.dev">
      <MyApp />
    </AuthProvider>
  );
}

function MyApp() {
  const { 
    user, 
    isLoading, 
    isAuthenticated,
    loginWithGithub, 
    loginWithGoogle, 
    logout,
    client 
  } = useAuth();

  if (isLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return (
      <div>
        <button onClick={() => loginWithGithub()}>
          Sign in with GitHub
        </button>
        <button onClick={() => loginWithGithub({ scopes: ['repo'] })}>
          Sign in with GitHub + Repo Access
        </button>
        <button onClick={() => loginWithGoogle()}>
          Sign in with Google
        </button>
      </div>
    );
  }

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <p>Arweave: {user.arweave_address}</p>
      {user.github_access_token && (
        <p>GitHub Token: {user.github_access_token}</p>
      )}
      <button onClick={logout}>Sign out</button>
      
      <button onClick={async () => {
        const result = await client.dispatch({
          data: 'Hello from React!',
          tags: [{ name: 'Content-Type', value: 'text/plain' }]
        });
        alert(`Uploaded: ${result.id}`);
      }}>
        Upload to Arweave
      </button>
    </div>
  );
}
```

## User Object

After login, the user object contains:

```typescript
type WauthUser = {
  id: string;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  
  // GitHub (if logged in via GitHub)
  github_id: number | null;
  github_username: string | null;
  github_access_token: string | null;
  
  // Google (if logged in via Google)
  google_id: string | null;
  google_access_token: string | null;
  
  // Arweave wallet
  arweave_address: string | null;
  
  created_at: string;
  updated_at: string;
};
```

## Auth State

Subscribe to auth state changes:

```typescript
const unsubscribe = client.onAuthChange((state) => {
  console.log('Auth changed:', state);
  // { user, token, isLoading, isAuthenticated }
});

// Later: unsubscribe()
```

## Self-Hosting

### Prerequisites

- [Bun](https://bun.sh) or Node.js
- Cloudflare account (for Workers + D1)
- GitHub OAuth app
- Google OAuth credentials

### 1. Set Up OAuth Apps

**GitHub:**
1. Go to GitHub Settings > Developer settings > OAuth Apps > New OAuth App
2. Set callback URL to `https://your-worker.workers.dev/auth/github/callback`
3. Copy Client ID and Secret

**Google:**
1. Go to Google Cloud Console > APIs & Services > Credentials
2. Create OAuth 2.0 Client ID (Web application)
3. Add `https://your-worker.workers.dev/auth/google/callback` to redirect URIs
4. Copy Client ID and Secret

### 2. Deploy Worker

```bash
cd worker

# Create D1 database
wrangler d1 create arlinkauth-db
wrangler d1 execute arlinkauth-db --remote --file=./schema.sql

# Set secrets
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put JWT_SECRET           # openssl rand -base64 32
wrangler secret put WALLET_ENCRYPTION_KEY # openssl rand -base64 32
wrangler secret put FRONTEND_URL         # fallback origin, e.g. https://myapp.com

# Deploy
wrangler deploy
```

### 3. Local Development

```bash
# Clone and install
git clone <repo-url>
cd arlinkauth
bun install

# Configure
cd worker
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your OAuth credentials

# Run everything
cd ..
bun run dev
```

This starts:
- Worker at http://localhost:8787
- Frontend at http://localhost:3000
- SDK in watch mode

## API Reference

### Endpoints

| Endpoint             | Method | Auth | Description                                       |
| -------------------- | ------ | ---- | ------------------------------------------------- |
| `/auth/github`       | GET    | No   | Start GitHub OAuth (supports `?scopes=repo,gist`) |
| `/auth/google`       | GET    | No   | Start Google OAuth                                |
| `/api/me`            | GET    | Yes  | Get current user                                  |
| `/api/wallet/action` | POST   | Yes  | Sign/dispatch data                                |

### Wallet Actions

All require `Authorization: Bearer <token>` header.

**Sign data item:**
```bash
curl -X POST https://worker.dev/api/wallet/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "signDataItem",
    "payload": {
      "data": "Hello Arweave",
      "tags": [{"name": "Content-Type", "value": "text/plain"}]
    }
  }'
```

**Dispatch (sign + upload):**
```bash
curl -X POST https://worker.dev/api/wallet/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "dispatch",
    "payload": {
      "data": "Hello Arweave",
      "tags": [{"name": "Content-Type", "value": "text/plain"}],
      "bundler": "turbo"
    }
  }'
```

**Raw signature:**
```bash
curl -X POST https://worker.dev/api/wallet/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "signature",
    "payload": { "data": "message to sign" }
  }'
```

## Security

- Wallet keys encrypted with AES-256-GCM
- PBKDF2 key derivation (100k iterations)
- JWTs expire after 7 days
- Rate limiting: 60 req/min (API), 10 req/min (auth)
- Input validation with Zod
- CORS allows all origins (for SDK flexibility)

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Your App      │────▶│  Cloudflare      │────▶│  GitHub/    │
│   (SDK)         │     │  Worker          │     │  Google     │
└─────────────────┘     └──────────────────┘     └─────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  D1 Database     │
                        │  - users         │
                        │  - wallets       │
                        └──────────────────┘
```

- **SDK** runs in browser, opens popup for OAuth
- **Worker** handles OAuth, stores encrypted wallets, signs transactions
- **D1** stores user accounts and encrypted wallet keys
- Accounts with same email across providers are automatically linked

## Limitations

- Custodial wallets (server holds keys)
- No wallet export
- No wallet import
- Single wallet per user

For non-custodial wallets, use [ArConnect](https://arconnect.io) instead.

## License

MIT
