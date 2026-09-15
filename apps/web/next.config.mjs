/** @type {import('next').NextConfig} */
const nextConfig = {
  // Minimal server bundle for containerized deployment.
  output: 'standalone',
  // Workspace packages ship TypeScript source (monorepo convention) —
  // compile them through Next rather than requiring a build step.
  transpilePackages: [
    '@agent-trust/attacks',
    '@agent-trust/audit',
    '@agent-trust/crypto',
    '@agent-trust/delegation',
    '@agent-trust/did',
    '@agent-trust/gateway',
    '@agent-trust/policy',
    '@agent-trust/replay',
    '@agent-trust/schemas',
    '@agent-trust/status',
    '@agent-trust/trust-profile',
    '@agent-trust/vc',
  ],
  webpack: (config) => {
    // Workspace packages are NodeNext ESM (`./x.js` specifiers) with .ts
    // sources — point webpack's resolver at the TS files first.
    config.resolve.extensionAlias = {
      ...(config.resolve.extensionAlias ?? {}),
      '.js': ['.ts', '.tsx', '.js'],
    };
    return config;
  },
  // STEP 16Q — baseline production hardening. CSP keeps Next's required
  // inline bootstrap scripts (framework requirement) but locks everything
  // else down: self-only sources, no framing, no object embeds.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Content-Security-Policy',
            value:
              "default-src 'self'; " +
              "script-src 'self' 'unsafe-inline'; " +
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
              "font-src 'self' https://fonts.gstatic.com; " +
              "img-src 'self' data:; " +
              "connect-src 'self'; " +
              "frame-ancestors 'none'; " +
              "base-uri 'self'; " +
              "form-action 'self'; " +
              "object-src 'none'",
          },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};

export default nextConfig;
