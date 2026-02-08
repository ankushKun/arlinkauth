import { type WauthClientOptions, type WauthUser, type AuthState, type AuthChangeListener, type OAuthProvider, type GitHubLoginOptions, type GoogleLoginOptions, type SignTransactionInput, type SignTransactionResult, type SignDataItemInput, type SignDataItemResult, type SignatureInput, type SignatureResult, type DispatchInput, type DispatchResult } from "./types.js";
/** Result returned after successful login */
export type LoginResult = {
    success: true;
    user: WauthUser;
} | {
    success: false;
};
export declare function createWauthClient(options: WauthClientOptions): {
    init: () => Promise<AuthState>;
    login: (options?: GitHubLoginOptions) => Promise<LoginResult>;
    loginWithGithub: (options?: GitHubLoginOptions) => Promise<LoginResult>;
    loginWithGoogle: (options?: GoogleLoginOptions) => Promise<LoginResult>;
    loginWithProvider: (provider: OAuthProvider, options?: {
        scopes?: string[];
    }) => Promise<LoginResult>;
    logout: () => void;
    handleCallback: () => boolean;
    isAuthenticated: () => boolean;
    getToken: () => string | null;
    getState: () => AuthState;
    onAuthChange: (listener: AuthChangeListener) => () => void;
    api: {
        getMe: () => Promise<WauthUser>;
    };
    sign: (input: SignTransactionInput) => Promise<SignTransactionResult>;
    signDataItem: (input: SignDataItemInput) => Promise<SignDataItemResult>;
    signature: (input: SignatureInput) => Promise<SignatureResult>;
    dispatch: (input: DispatchInput) => Promise<DispatchResult>;
};
export type WauthClient = ReturnType<typeof createWauthClient>;
