/** @type {import('next').NextConfig} */
const nextConfig = {
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
};

export default nextConfig;
