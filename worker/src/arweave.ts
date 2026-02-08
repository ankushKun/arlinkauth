/**
 * Arweave wallet generation utilities for Cloudflare Workers.
 * Uses Web Crypto API to generate RSA-4096 keys compatible with Arweave.
 */

import Arweave from "arweave";

const arweave = Arweave.init({
  host: "arweave.net",
  port: 443,
  protocol: "https",
});

/**
 * Generate a new Arweave wallet (JWK) and derive the address.
 */
export async function generateArweaveWallet(): Promise<{
  jwk: JsonWebKey;
  address: string;
}> {
  const jwk = await arweave.wallets.generate();
  const address = await arweave.wallets.jwkToAddress(jwk);

  return { jwk, address };
}
