/**
 * Release identity shown by /api/health and /api/demo/status.
 *
 * Render sets RENDER_GIT_COMMIT for every deploy, so it wins: a stale
 * DEMO_BUILD_SHA left over from an earlier release can never mislabel the
 * running build. DEMO_BUILD_SHA remains the fallback for other hosts.
 */
export function buildSha(): string {
  const platform = process.env.RENDER_GIT_COMMIT?.trim();
  if (platform !== undefined && platform !== '') return platform.slice(0, 7);
  const manual = process.env.DEMO_BUILD_SHA?.trim();
  return manual !== undefined && manual !== '' ? manual : 'dev';
}
