export { createWauthClient, createWauthClient as createArlinkAuthClient } from "./client.js";
export type { WauthClient, WauthClient as ArlinkAuthClient, LoginResult } from "./client.js";
export {
  WalletAction,
  type WauthUser,
  type WauthUser as ArlinkUser,
  type WauthClientOptions,
  type WauthClientOptions as ArlinkAuthClientOptions,
  type AuthState,
  type AuthChangeListener,
  type OAuthProvider,
  type GitHubLoginOptions,
  type GoogleLoginOptions,
  type ArweaveTag,
  type SignTransactionInput,
  type SignTransactionResult,
  type SignDataItemInput,
  type SignDataItemResult,
  type SignatureInput,
  type SignatureResult,
  type BundlerType,
  type DispatchInput,
  type DispatchResult,
} from "./types.js";