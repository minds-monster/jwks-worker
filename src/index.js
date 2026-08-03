import * as jose from 'jose';

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'GET') {
      try {
        const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${env.PARTNER_PUBLIC_KEY}\n-----END PUBLIC KEY-----`;
        const publicKey = await jose.importSPKI(publicKeyPem, 'RS256');
        const jwk = await jose.exportJWK(publicKey);
        
        return new Response(JSON.stringify({ 
          keys: [{
            ...jwk,
            kid: env.PARTNER_ID || '3dd91077-c6db-4cb6-9f8d-1d603b85f8ee',
            alg: 'RS256',
            use: 'sig'
          }] 
        }), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=3600',
          },
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Failed to generate JWKS' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }
    return new Response('Method not allowed', { status: 405 });
  },
};