import { afterEach, describe, expect, it, vi } from 'vitest';

import { GET as health } from '../src/app/api/health/route';
import { buildSha } from '../src/server/build-info';

describe('build identity', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('platform commit wins over a stale DEMO_BUILD_SHA and is shortened to 7 chars', () => {
    vi.stubEnv('RENDER_GIT_COMMIT', 'a5eb08e3ac01b2b680a9fe982902e113910340f7');
    vi.stubEnv('DEMO_BUILD_SHA', '4c25b4b');
    expect(buildSha()).toBe('a5eb08e');
  });

  it('falls back to DEMO_BUILD_SHA, then to "dev"', () => {
    vi.stubEnv('RENDER_GIT_COMMIT', '');
    vi.stubEnv('DEMO_BUILD_SHA', 'abc1234');
    expect(buildSha()).toBe('abc1234');
    vi.stubEnv('DEMO_BUILD_SHA', '');
    expect(buildSha()).toBe('dev');
  });

  it('/api/health reports the platform commit', async () => {
    vi.stubEnv('RENDER_GIT_COMMIT', 'deadbeefcafe0000');
    const json = await health().json();
    expect(json.build.sha).toBe('deadbee');
  });
});
