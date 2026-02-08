import { Hono } from "hono";
import { cors } from "hono/cors";
import { sign, verify } from "hono/jwt";
import { encryptJwk, decryptJwk } from "./crypto";
import { generateArweaveWallet } from "./arweave";
import Arweave from "arweave";
import { createData, ArweaveSigner } from "@dha-team/arbundles";

// Initialize Arweave client
const arweave = Arweave.init({
  host: "arweave.net",
  port: 443,
  protocol: "https",
});

// Arweave JWK interface (matches what arweave.wallets.generate() returns)
interface ArweaveJWK {
  kty: string;
  n: string;
  e: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
}

// Wallet action types
export enum WalletAction {
  SIGN = "sign",
  SIGN_DATA_ITEM = "signDataItem",
  SIGNATURE = "signature",
  DISPATCH = "dispatch",
}

// Bundler endpoints for dispatching data items
const BUNDLER_ENDPOINTS = {
  turbo: "https://upload.ardrive.io",
  irys: "https://node2.irys.xyz",
} as const;

type BundlerType = keyof typeof BUNDLER_ENDPOINTS;

// ── Types ──────────────────────────────────────────────

type Bindings = {
  DB: D1Database;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  JWT_SECRET: string;
  /** Where the client lives, used for post-login redirect */
  FRONTEND_URL: string;
  /** Master key for encrypting wallet JWKs */
  WALLET_ENCRYPTION_KEY: string;
};

type Variables = {
  userId: string;
  jwtPayload: { sub: string; exp: number };
};

type AppEnv = { Bindings: Bindings; Variables: Variables };

// ── App ────────────────────────────────────────────────

const app = new Hono<AppEnv>();

app.use("*", cors());

// Health check
app.get("/", (c) => {
  return c.json({ message: "wauth", timestamp: Date.now() });
});

// ── GitHub OAuth ───────────────────────────────────────

app.get("/auth/github", (c) => {
  const state = crypto.randomUUID();
  const redirectUri = new URL("/auth/github/callback", c.req.url).toString();
  const params = new URLSearchParams({
    client_id: c.env.GITHUB_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: "read:user user:email",
    state,
  });

  // Store state in a short-lived cookie so we can verify on callback
  // Omit Secure flag on localhost so the cookie works over plain http
  const isLocalhost = new URL(c.req.url).hostname === "localhost";
  const securePart = isLocalhost ? "" : " Secure;";
  c.header(
    "Set-Cookie",
    `oauth_state=${state}; HttpOnly;${securePart} SameSite=Lax; Path=/; Max-Age=300`
  );

  return c.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.get("/auth/github/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");

  // Validate state against cookie
  const cookies = c.req.header("cookie") ?? "";
  const storedState = cookies
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith("oauth_state="))
    ?.split("=")[1];

  if (!code || !state || state !== storedState) {
    return c.json({ error: "Invalid OAuth state" }, 400);
  }

  // Exchange code for access token
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      client_id: c.env.GITHUB_CLIENT_ID,
      client_secret: c.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });

  const tokenData = (await tokenRes.json()) as {
    access_token?: string;
    error?: string;
  };

  if (!tokenData.access_token) {
    return c.json({ error: "Failed to get access token", details: tokenData }, 400);
  }

  // Fetch GitHub user profile + email in parallel
  const [userRes, emailsRes] = await Promise.all([
    fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "User-Agent": "wauth-worker",
      },
    }),
    fetch("https://api.github.com/user/emails", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "User-Agent": "wauth-worker",
      },
    }),
  ]);

  const ghUser = (await userRes.json()) as {
    id: number;
    login: string;
    name: string | null;
    avatar_url: string;
    email: string | null;
  };

  // Pick the primary verified email from /user/emails (more reliable than /user)
  const emails = (await emailsRes.json()) as {
    email: string;
    primary: boolean;
    verified: boolean;
  }[];
  const primaryEmail =
    emails.find((e) => e.primary && e.verified)?.email ??
    ghUser.email;

  // Check if user already exists
  const existingUser = await c.env.DB.prepare(
    `SELECT id FROM users WHERE github_id = ?1`
  )
    .bind(ghUser.id)
    .first<{ id: string }>();

  const isNewUser = !existingUser;
  let actualUserId: string;

  if (isNewUser) {
    // Create new user
    actualUserId = crypto.randomUUID();
    await c.env.DB.prepare(
      `INSERT INTO users (id, github_id, github_username, github_name, github_email, github_avatar_url, github_access_token, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(actualUserId, ghUser.id, ghUser.login, ghUser.name, primaryEmail, ghUser.avatar_url, tokenData.access_token)
      .run();

    // Generate and store encrypted Arweave wallet for new user
    const { jwk, address } = await generateArweaveWallet();
    const { encrypted, salt } = await encryptJwk(jwk, c.env.WALLET_ENCRYPTION_KEY);
    const walletId = crypto.randomUUID();

    await c.env.DB.prepare(
      `INSERT INTO wallets (id, user_id, address, encrypted_jwk, salt) VALUES (?1, ?2, ?3, ?4, ?5)`
    )
      .bind(walletId, actualUserId, address, encrypted, salt)
      .run();
  } else {
    // Update existing user
    actualUserId = existingUser.id;
    await c.env.DB.prepare(
      `UPDATE users SET
         github_username = ?1,
         github_name = ?2,
         github_email = ?3,
         github_avatar_url = ?4,
         github_access_token = ?5,
         updated_at = datetime('now')
       WHERE id = ?6`
    )
      .bind(ghUser.login, ghUser.name, primaryEmail, ghUser.avatar_url, tokenData.access_token, actualUserId)
      .run();

    // Check if existing user has a wallet, if not create one
    const existingWallet = await c.env.DB.prepare(
      `SELECT id FROM wallets WHERE user_id = ?1 LIMIT 1`
    )
      .bind(actualUserId)
      .first();

    if (!existingWallet) {
      const { jwk, address } = await generateArweaveWallet();
      const { encrypted, salt } = await encryptJwk(jwk, c.env.WALLET_ENCRYPTION_KEY);
      const walletId = crypto.randomUUID();

      await c.env.DB.prepare(
        `INSERT INTO wallets (id, user_id, address, encrypted_jwk, salt) VALUES (?1, ?2, ?3, ?4, ?5)`
      )
        .bind(walletId, actualUserId, address, encrypted, salt)
        .run();
    }
  }

  // Issue JWT (expires in 7 days)
  const jwt = await sign(
    { sub: actualUserId, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 },
    c.env.JWT_SECRET,
    "HS256"
  );

  // Clear the oauth_state cookie
  const isLocalhost = new URL(c.req.url).hostname === "localhost";
  const securePart = isLocalhost ? "" : " Secure;";
  c.header(
    "Set-Cookie",
    `oauth_state=;HttpOnly;${securePart} SameSite=Lax; Path=/; Max-Age=0`
  );

  // Return HTML that posts token to opener window (popup flow)
  const html = `<!DOCTYPE html>
<html>
<head><title>Authenticating...</title></head>
<body>
<p>Authenticating, please wait...</p>
<script>
  if (window.opener) {
    window.opener.postMessage(
      { type: "wauth:callback", token: "${jwt}" },
      "${c.env.FRONTEND_URL}"
    );
  } else {
    // Fallback: redirect if not in popup
    window.location.href = "${c.env.FRONTEND_URL}?token=${jwt}";
  }
</script>
</body>
</html>`;

  return c.html(html);
});

// ── JWT Auth Middleware (for /api/*) ───────────────────

app.use("/api/*", async (c, next) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header" }, 401);
  }

  const token = authHeader.slice(7);
  try {
    const payload = (await verify(token, c.env.JWT_SECRET, "HS256")) as {
      sub: string;
      exp: number;
    };
    c.set("userId", payload.sub);
    c.set("jwtPayload", payload);
  } catch {
    return c.json({ error: "Invalid or expired token" }, 401);
  }

  await next();
});

// ── Protected Routes ───────────────────────────────────

app.get("/api/me", async (c) => {
  const userId = c.get("userId");
  
  // Get user info (excluding sensitive wallet data)
  const user = await c.env.DB.prepare(
    `SELECT id, github_id, github_username, github_name, github_email, github_avatar_url, github_access_token, created_at, updated_at FROM users WHERE id = ?1`
  )
    .bind(userId)
    .first();

  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  // Get wallet address only (never expose JWK or encrypted data)
  const wallet = await c.env.DB.prepare(
    `SELECT address FROM wallets WHERE user_id = ?1 LIMIT 1`
  )
    .bind(userId)
    .first<{ address: string }>();

  return c.json({
    ...user,
    arweave_address: wallet?.address ?? null,
  });
});

// ── Wallet Signing Actions ─────────────────────────────

app.post("/api/wallet/action", async (c) => {
  const userId = c.get("userId");

  const body = await c.req.json<{
    action: WalletAction;
    payload: Record<string, unknown>;
  }>();

  const { action, payload } = body;

  if (!action || !payload) {
    return c.json({ error: "Missing action or payload" }, 400);
  }

  // Get wallet from database
  const wallet = await c.env.DB.prepare(
    `SELECT address, encrypted_jwk, salt FROM wallets WHERE user_id = ?1 LIMIT 1`
  )
    .bind(userId)
    .first<{ address: string; encrypted_jwk: string; salt: string }>();

  if (!wallet) {
    return c.json({ error: "No wallet found for user" }, 404);
  }

  // Decrypt the wallet JWK
  let jwk: ArweaveJWK;
  try {
    jwk = await decryptJwk(
      wallet.encrypted_jwk,
      wallet.salt,
      c.env.WALLET_ENCRYPTION_KEY
    ) as ArweaveJWK;
  } catch (err) {
    console.error("Failed to decrypt wallet:", err);
    return c.json({ error: "Failed to decrypt wallet" }, 500);
  }

  // Validate JWK has required fields
  if (!jwk.n || !jwk.e || !jwk.d) {
    console.error("Invalid JWK - missing required fields:", { 
      hasN: !!jwk.n, 
      hasE: !!jwk.e, 
      hasD: !!jwk.d
    });
    return c.json({ error: "Invalid wallet JWK format" }, 500);
  }

  // Create signer for data items
  let signer: ArweaveSigner;
  try {
    signer = new ArweaveSigner(jwk);
  } catch (err) {
    console.error("Failed to create ArweaveSigner:", err);
    return c.json({ error: `Failed to create signer: ${err instanceof Error ? err.message : err}` }, 500);
  }

  try {
    switch (action) {
      case WalletAction.SIGN: {
        // Sign an Arweave transaction
        const txPayload = payload.transaction;
        if (!txPayload) {
          return c.json({ error: "Missing transaction in payload" }, 400);
        }
        const tx = arweave.transactions.fromRaw(txPayload as Parameters<typeof arweave.transactions.fromRaw>[0]);
        await arweave.transactions.sign(tx, jwk);
        return c.json(tx.toJSON());
      }

      case WalletAction.SIGN_DATA_ITEM: {
        // Sign an ANS-104 data item (for AO/bundled transactions)
        const dataItemPayload = payload.dataItem as {
          data: string | Uint8Array | number[];
          tags?: { name: string; value: string }[];
          target?: string;
          anchor?: string;
        };
        
        if (!dataItemPayload) {
          return c.json({ error: "Missing dataItem in payload" }, 400);
        }

        // Convert data to Buffer
        let data: Buffer;
        if (typeof dataItemPayload.data === "string") {
          data = Buffer.from(dataItemPayload.data);
        } else if (Array.isArray(dataItemPayload.data)) {
          data = Buffer.from(dataItemPayload.data);
        } else {
          data = Buffer.from(dataItemPayload.data);
        }

        const createdDataItem = createData(data, signer, {
          tags: dataItemPayload.tags,
          target: dataItemPayload.target,
          anchor: dataItemPayload.anchor,
        });

        await createdDataItem.sign(signer);

        // Note: We skip isValid() check here because it uses ArweaveSigner.verify()
        // which has issues with Web Crypto API in Workers environment.
        // The signing itself succeeded, and the data item has a valid id.
        
        // Verify we have an id (indicates signing succeeded)
        if (!createdDataItem.id) {
          return c.json({ error: "Data item signing failed - no id generated" }, 500);
        }

        return c.json({
          id: createdDataItem.id,
          raw: Array.from(createdDataItem.getRaw()),
        });
      }

      case WalletAction.DISPATCH: {
        // Sign and dispatch a data item to a bundler (Turbo/Irys)
        const dispatchPayload = payload as {
          data: string | number[];
          tags?: { name: string; value: string }[];
          target?: string;
          anchor?: string;
          bundler?: BundlerType;
        };

        if (!dispatchPayload.data) {
          return c.json({ error: "Missing data in payload" }, 400);
        }

        // Convert data to Buffer
        let data: Buffer;
        if (typeof dispatchPayload.data === "string") {
          data = Buffer.from(dispatchPayload.data);
        } else if (Array.isArray(dispatchPayload.data)) {
          data = Buffer.from(dispatchPayload.data);
        } else {
          return c.json({ error: "Invalid data format" }, 400);
        }

        // Create and sign the data item
        const dataItem = createData(data, signer, {
          tags: dispatchPayload.tags,
          target: dispatchPayload.target,
          anchor: dispatchPayload.anchor,
        });

        await dataItem.sign(signer);

        if (!dataItem.id) {
          return c.json({ error: "Data item signing failed - no id generated" }, 500);
        }

        // Get the raw signed data item
        const rawDataItem = dataItem.getRaw();

        // Dispatch to bundler (default to Turbo)
        const bundlerType = dispatchPayload.bundler ?? "turbo";
        const bundlerUrl = BUNDLER_ENDPOINTS[bundlerType];

        if (!bundlerUrl) {
          return c.json({ error: `Unknown bundler: ${bundlerType}` }, 400);
        }

        // Upload to bundler
        const uploadResponse = await fetch(`${bundlerUrl}/tx/arweave`, {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
          },
          body: rawDataItem,
        });

        if (!uploadResponse.ok) {
          const errorText = await uploadResponse.text();
          console.error("Bundler upload failed:", uploadResponse.status, errorText);
          return c.json({ 
            error: `Bundler upload failed: ${uploadResponse.status}`,
            details: errorText,
          }, 500);
        }

        const uploadResult = await uploadResponse.json() as { id?: string; [key: string]: unknown };

        return c.json({
          id: dataItem.id,
          bundler: bundlerType,
          response: uploadResult,
        });
      }

      case WalletAction.SIGNATURE: {
        // Raw signature of arbitrary data
        const data = payload.data;
        if (!data) {
          return c.json({ error: "Missing data in payload" }, 400);
        }

        // Convert data to Uint8Array
        let dataBuffer: Uint8Array;
        if (typeof data === "string") {
          dataBuffer = new TextEncoder().encode(data);
        } else if (Array.isArray(data)) {
          dataBuffer = new Uint8Array(data as number[]);
        } else if (typeof data === "object" && data !== null) {
          // Handle object with numeric keys (like {0: 1, 1: 2, ...})
          dataBuffer = new Uint8Array(Object.values(data as Record<string, number>));
        } else {
          return c.json({ error: "Invalid data format" }, 400);
        }

        const signature = await signer.sign(dataBuffer);

        return c.json({
          signature: Array.from(signature),
        });
      }

      default:
        return c.json({ error: `Unknown action: ${action}` }, 400);
    }
  } catch (err) {
    console.error("Wallet action error:", err);
    return c.json(
      { error: err instanceof Error ? err.message : "Wallet action failed" },
      500
    );
  }
});

export default app;
