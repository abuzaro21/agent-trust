#!/usr/bin/env node
/**
 * Install the pinned OPA CLI (v1.20.2) into tools/bin for local
 * development. CI installs it system-wide instead (see ci.yml).
 */
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const OPA_VERSION = 'v1.20.2';
const ROOT = import.meta.dirname ? join(import.meta.dirname, '..') : process.cwd();
const BIN_DIR = join(ROOT, 'tools', 'bin');

const ASSETS = {
  'win32-x64': { name: 'opa_windows_amd64.exe', out: 'opa.exe' },
  'linux-x64': { name: 'opa_linux_amd64_static', out: 'opa' },
  'linux-arm64': { name: 'opa_linux_arm64_static', out: 'opa' },
  'darwin-x64': { name: 'opa_darwin_amd64', out: 'opa' },
  'darwin-arm64': { name: 'opa_darwin_arm64_static', out: 'opa' },
};

const key = `${process.platform}-${process.arch}`;
const asset = ASSETS[key];
if (!asset) {
  console.error(`No pinned OPA asset for ${key}; install OPA ${OPA_VERSION} manually.`);
  process.exit(1);
}

const dest = join(BIN_DIR, asset.out);
if (existsSync(dest)) {
  console.log(`OPA already installed: ${dest}`);
  process.exit(0);
}

const url = `https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/${asset.name}`;
console.log(`Downloading ${url}`);
const response = await fetch(url);
if (!response.ok) {
  console.error(`Download failed: HTTP ${response.status}`);
  process.exit(1);
}
const bytes = Buffer.from(await response.arrayBuffer());
mkdirSync(BIN_DIR, { recursive: true });
writeFileSync(dest, bytes);
chmodSync(dest, 0o755);
console.log(`OPA ${OPA_VERSION} installed: ${dest}`);
console.log(`sha256: ${createHash('sha256').update(bytes).digest('hex')}`);
