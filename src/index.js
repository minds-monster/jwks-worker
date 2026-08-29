import * as jose from 'jose';

/**
 * Default issuer signing key (EC P-256, kid b49b6217-...).
 *
 * This is public key material already published at the live JWKS endpoint.
 * It is hardcoded only as a fallback; the preferred source is the ISSUER_JWKS
 * environment variable, which can hold one or more issuer keys.
 */
const DEFAULT_ISSUER_JWKS = {
  keys: [
    {
      kid: 'b49b6217-e54a-4557-980e-2ac494629114',
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
      x: 'suBinUJqU9hjCoIMF7F579EGx3OTsk-GAesSqFRkz8s',
      y: '-SZgaZP30CDN6aLicGe4GeGlVozHyNuPcqSIG5MO5Jw',
    },
  ],
};

/**
 * Build the partner-auth RSA key JWK from a PEM public key.
 *
 * The private key that signs x-partner-auth JWTs must never reach this Worker;
 * only the public key is published here.
 */
async function partnerJwk(env) {
  if (!env.PARTNER_PUBLIC_KEY) return null;

  const pem = env.PARTNER_PUBLIC_KEY.includes('-----BEGIN PUBLIC KEY-----')
    ? env.PARTNER_PUBLIC_KEY
    : `-----BEGIN PUBLIC KEY-----\n${env.PARTNER_PUBLIC_KEY}\n-----END PUBLIC KEY-----`;

  const key = await jose.importSPKI(pem, 'RS256');
  const jwk = await jose.exportJWK(key);

  return {
    ...jwk,
    kid: env.PARTNER_ID || 'd4d4049f-3321-4e6a-8f87-fc3b52008bc9',
    alg: 'RS256',
    use: 'sig',
  };
}

/**
 * Read issuer signing keys from env, falling back to the compiled default.
 *
 * Accepts either a bare keys array or a { keys: [...] } object so it can be
 * copied straight from an SD_JWT_JWKS-style config value.
 */
function issuerKeys(env) {
  if (!env.ISSUER_JWKS) return DEFAULT_ISSUER_JWKS.keys;

  try {
    const parsed = JSON.parse(env.ISSUER_JWKS);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.keys)) return parsed.keys;
  } catch {
    // Fall through to default on malformed env var.
  }
  return DEFAULT_ISSUER_JWKS.keys;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method !== 'GET') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const keys = [...issuerKeys(env)];
      const partner = await partnerJwk(env);
      if (partner) keys.push(partner);

      if (!keys.length) {
        throw new Error('No keys configured');
      }

      return new Response(JSON.stringify({ keys }), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=3600',
        },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({ error: 'Failed to generate JWKS', message: error.message }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }
  },
};
