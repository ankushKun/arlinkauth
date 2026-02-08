import { useAuth } from "@wauth/sdk/react";
import type { WauthUser, SignDataItemResult, SignatureResult, DispatchResult } from "@wauth/sdk";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";

function LoginScreen({ login }: { login: () => void }) {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-2xl">Welcome to wauth</CardTitle>
          <CardDescription>Sign in with your GitHub account to continue.</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={login} className="w-full" size="lg">
            Sign in with GitHub
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function LoadingScreen() {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <p className="text-muted-foreground">Loading...</p>
    </div>
  );
}

// ── Detail row helper ─────────────────────────────────

function DetailRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex justify-between items-start gap-4 py-2 border-b last:border-b-0">
      <span className="text-sm text-muted-foreground shrink-0">{label}</span>
      <span className="text-sm text-right break-all">{value ?? "N/A"}</span>
    </div>
  );
}

// ── User Profile Card ─────────────────────────────────

function UserProfile({ user }: { user: WauthUser }) {
  const [showToken, setShowToken] = useState(false);

  return (
    <div className="space-y-4">
      {/* Avatar + name header */}
      <div className="flex items-center gap-4">
        {user.github_avatar_url && (
          <img
            src={user.github_avatar_url}
            alt={user.github_username}
            className="w-16 h-16 rounded-full border"
          />
        )}
        <div>
          <p className="font-semibold text-lg">{user.github_name ?? user.github_username}</p>
          <a
            href={`https://github.com/${user.github_username}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground hover:underline"
          >
            @{user.github_username}
          </a>
        </div>
      </div>

      {/* Details */}
      <div className="rounded-lg border p-4">
        <DetailRow label="User ID" value={user.id} />
        <DetailRow label="GitHub ID" value={String(user.github_id)} />
        <DetailRow label="Email" value={user.github_email} />
        <DetailRow label="Name" value={user.github_name} />
        <DetailRow label="Arweave Address" value={user.arweave_address} />
        <DetailRow label="Member since" value={user.created_at} />
        <DetailRow label="Last updated" value={user.updated_at} />

        {/* Token with show/hide toggle */}
        <div className="flex justify-between items-start gap-4 py-2">
          <span className="text-sm text-muted-foreground shrink-0">GitHub Token</span>
          <div className="flex flex-col items-end gap-1">
            <button
              onClick={() => setShowToken(!showToken)}
              className="text-xs text-primary hover:underline"
            >
              {showToken ? "Hide" : "Reveal"}
            </button>
            {showToken && (
              <code className="text-xs bg-muted px-2 py-1 rounded break-all max-w-[280px]">
                {user.github_access_token}
              </code>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Signing Demo Card ──────────────────────────────────

function SigningDemo() {
  const { client } = useAuth();
  const [message, setMessage] = useState("Hello from wauth!");
  const [signatureResult, setSignatureResult] = useState<SignatureResult | null>(null);
  const [dataItemResult, setDataItemResult] = useState<SignDataItemResult | null>(null);
  const [isSigningMessage, setIsSigningMessage] = useState(false);
  const [isSigningDataItem, setIsSigningDataItem] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSignMessage = async () => {
    setError(null);
    setSignatureResult(null);
    setIsSigningMessage(true);
    try {
      const result = await client.signature({ data: message });
      setSignatureResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to sign message");
    } finally {
      setIsSigningMessage(false);
    }
  };

  const handleSignDataItem = async () => {
    setError(null);
    setDataItemResult(null);
    setIsSigningDataItem(true);
    try {
      const result = await client.signDataItem({
        data: message,
        tags: [
          { name: "Content-Type", value: "text/plain" },
          { name: "App-Name", value: "wauth-demo" },
        ],
      });
      setDataItemResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to sign data item");
    } finally {
      setIsSigningDataItem(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <label className="text-sm font-medium">Message to sign</label>
        <Input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter a message..."
        />
      </div>

      <div className="flex gap-2">
        <Button
          onClick={handleSignMessage}
          disabled={isSigningMessage || !message}
          variant="secondary"
          className="flex-1"
        >
          {isSigningMessage ? "Signing..." : "Sign Message"}
        </Button>
        <Button
          onClick={handleSignDataItem}
          disabled={isSigningDataItem || !message}
          variant="secondary"
          className="flex-1"
        >
          {isSigningDataItem ? "Signing..." : "Sign Data Item"}
        </Button>
      </div>

      {error && (
        <div className="p-3 bg-destructive/10 text-destructive rounded-lg text-sm">
          {error}
        </div>
      )}

      {signatureResult && (
        <div className="space-y-2">
          <p className="text-sm font-medium">Raw Signature</p>
          <div className="p-3 bg-muted rounded-lg">
            <code className="text-xs break-all">
              {signatureResult.signature.slice(0, 64).join(", ")}...
              <br />
              <span className="text-muted-foreground">
                ({signatureResult.signature.length} bytes)
              </span>
            </code>
          </div>
        </div>
      )}

      {dataItemResult && (
        <div className="space-y-2">
          <p className="text-sm font-medium">Signed Data Item</p>
          <div className="p-3 bg-muted rounded-lg space-y-1">
            <p className="text-xs">
              <span className="text-muted-foreground">ID:</span>{" "}
              <code className="break-all">{dataItemResult.id}</code>
            </p>
            <p className="text-xs text-muted-foreground">
              Raw size: {dataItemResult.raw.length} bytes
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Dispatch Demo Card ──────────────────────────────────

function DispatchDemo() {
  const { client } = useAuth();
  const [message, setMessage] = useState("Hello from wauth! This is stored on Arweave.");
  const [dispatchResult, setDispatchResult] = useState<DispatchResult | null>(null);
  const [isDispatching, setIsDispatching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDispatch = async () => {
    setError(null);
    setDispatchResult(null);
    setIsDispatching(true);
    try {
      const result = await client.dispatch({
        data: message,
        tags: [
          { name: "Content-Type", value: "text/plain" },
          { name: "App-Name", value: "wauth-demo" },
          { name: "App-Version", value: "1.0.0" },
        ],
      });
      setDispatchResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to dispatch");
    } finally {
      setIsDispatching(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <label className="text-sm font-medium">Data to upload</label>
        <Input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter data to upload to Arweave..."
        />
      </div>

      <Button
        onClick={handleDispatch}
        disabled={isDispatching || !message}
        className="w-full"
      >
        {isDispatching ? "Uploading to Arweave..." : "Upload to Arweave"}
      </Button>

      {error && (
        <div className="p-3 bg-destructive/10 text-destructive rounded-lg text-sm">
          {error}
        </div>
      )}

      {dispatchResult && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-green-600">Uploaded successfully!</p>
          <div className="p-3 bg-muted rounded-lg space-y-2">
            <p className="text-xs">
              <span className="text-muted-foreground">Transaction ID:</span>{" "}
              <code className="break-all">{dispatchResult.id}</code>
            </p>
            <p className="text-xs">
              <span className="text-muted-foreground">Bundler:</span>{" "}
              <code>{dispatchResult.bundler}</code>
            </p>
            <a
              href={`https://arweave.net/${dispatchResult.id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-primary hover:underline block"
            >
              View on Arweave Gateway
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Authenticated Screen ──────────────────────────────

function AuthenticatedScreen() {
  const { user, logout } = useAuth();

  return (
    <div className="flex items-center justify-center min-h-screen p-4">
      <div className="w-full max-w-lg space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-xl">Account</CardTitle>
            <CardDescription>Your GitHub profile and auth details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {user && <UserProfile user={user} />}
            <Button onClick={logout} variant="outline" className="w-full">
              Sign out
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-xl">Wallet Signing</CardTitle>
            <CardDescription>
              Test signing with your server-side Arweave wallet
            </CardDescription>
          </CardHeader>
          <CardContent>
            <SigningDemo />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-xl">Upload to Arweave</CardTitle>
            <CardDescription>
              Dispatch data to Arweave via Turbo bundler (free for small uploads)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DispatchDemo />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────

export function Dashboard() {
  const { isLoading, isAuthenticated, login } = useAuth();

  if (isLoading) return <LoadingScreen />;
  if (!isAuthenticated) return <LoginScreen login={login} />;
  return <AuthenticatedScreen />;
}
