/**
 * Sentinel AI Path — Environment Detection & Setup
 *
 * Detects OS, checks all dependencies, reports what's available.
 * An AI agent calls setup() first to understand what it can do.
 */

import {
  verifyDependencies,
  IS_ADMIN,
  WG_AVAILABLE,
  V2RAY_VERSION,
  preflight,
} from '../index.js';
import { existsSync } from 'fs';
import { execSync } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── V2Ray Detection (comprehensive) ────────────────────────────────────────

/**
 * Find V2Ray binary by checking every known location.
 * This is the authoritative detection — covers env var, SDK paths, system paths.
 */
function findV2Ray() {
  const binary = process.platform === 'win32' ? 'v2ray.exe' : 'v2ray';

  // 1. V2RAY_PATH env var (highest priority)
  if (process.env.V2RAY_PATH && existsSync(process.env.V2RAY_PATH)) {
    return process.env.V2RAY_PATH;
  }

  // 2. Use Node.js module resolution to find the SDK, then derive bin/ path
  try {
    const sdkMain = import.meta.resolve('sentinel-dvpn-sdk');
    const sdkDir = dirname(fileURLToPath(sdkMain));
    const sdkBin = resolve(sdkDir, 'bin', binary);
    if (existsSync(sdkBin)) return sdkBin;
  } catch {}

  // 3. Walk up from __dirname looking for sentinel-dvpn-sdk/bin/
  let dir = __dirname;
  for (let i = 0; i < 5; i++) {
    const candidate = resolve(dir, 'node_modules', 'sentinel-dvpn-sdk', 'bin', binary);
    if (existsSync(candidate)) return candidate;
    const sibling = resolve(dir, '..', 'sentinel-dvpn-sdk', 'bin', binary);
    if (existsSync(sibling)) return sibling;
    dir = resolve(dir, '..');
  }

  // 4. Local bin/
  const localBin = resolve(__dirname, 'bin', binary);
  if (existsSync(localBin)) return localBin;

  // 5. Parent bin/ (monorepo layout)
  const parentBin = resolve(__dirname, '..', 'bin', binary);
  if (existsSync(parentBin)) return parentBin;

  // 5. System paths
  const systemPaths = process.platform === 'win32'
    ? ['C:\\Program Files\\V2Ray\\v2ray.exe', 'C:\\Program Files (x86)\\V2Ray\\v2ray.exe']
    : ['/usr/local/bin/v2ray', '/usr/bin/v2ray', '/opt/homebrew/bin/v2ray'];
  for (const p of systemPaths) {
    if (existsSync(p)) return p;
  }

  // 6. System PATH
  try {
    const cmd = process.platform === 'win32' ? 'where v2ray.exe' : 'which v2ray';
    const result = execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (result) return result.split('\n')[0];
  } catch { /* not in PATH */ }

  return null;
}

// ─── WireGuard Detection (comprehensive) ─────────────────────────────────────

function findWireGuard() {
  if (process.platform === 'win32') {
    const paths = [
      'C:\\Program Files\\WireGuard\\wireguard.exe',
      'C:\\Program Files (x86)\\WireGuard\\wireguard.exe',
    ];
    for (const p of paths) {
      if (existsSync(p)) return p;
    }
  } else {
    const paths = ['/usr/bin/wg', '/usr/local/bin/wg', '/opt/homebrew/bin/wg'];
    for (const p of paths) {
      if (existsSync(p)) return p;
    }
  }
  try {
    const cmd = process.platform === 'win32' ? 'where wireguard.exe' : 'which wg';
    const result = execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (result) return result.split('\n')[0];
  } catch { /* not in PATH */ }
  return null;
}

// ─── V2Ray Auto-Install ──────────────────────────────────────────────────────

/**
 * Download V2Ray via the parent SDK's setup script (no admin rights needed).
 * Downloads the official v2fly release zip, verifies SHA256, unzips to the
 * SDK's bin/ directory — the same location findV2Ray() checks first.
 * Throws with context when the setup script is missing or the download fails.
 */
async function installV2Ray() {
  const parentSetup = resolve(__dirname, '..', 'setup.js');
  if (!existsSync(parentSetup)) {
    throw new Error(`SDK setup script not found at ${parentSetup} — reinstall blue-js-sdk`);
  }
  const mod = await import(pathToFileURL(parentSetup).href);
  if (typeof mod.setupV2Ray !== 'function') {
    throw new Error('SDK setup script does not export setupV2Ray() — blue-js-sdk version too old (need >= 2.8.0)');
  }
  await mod.setupV2Ray();
}

// ─── getEnvironment() ────────────────────────────────────────────────────────

/**
 * Detect the current environment without changing anything.
 * Uses comprehensive detection — checks env vars, SDK paths, system paths, PATH.
 *
 * @returns {{
 *   os: string,
 *   arch: string,
 *   platform: string,
 *   nodeVersion: string,
 *   admin: boolean,
 *   v2ray: { available: boolean, version: string|null, path: string|null },
 *   wireguard: { available: boolean, path: string|null, requiresAdmin: true },
 *   capabilities: string[],
 *   recommended: string[],
 * }}
 */
export function getEnvironment() {
  const os = process.platform === 'win32' ? 'windows'
    : process.platform === 'darwin' ? 'macos'
    : process.platform === 'linux' ? 'linux'
    : process.platform;

  // V2Ray: our own comprehensive detection (not just SDK's verifyDependencies)
  const v2rayPath = findV2Ray();
  let v2rayVersion = null;
  if (v2rayPath) {
    try {
      const out = execSync(`"${v2rayPath}" version`, { encoding: 'utf8', stdio: 'pipe', timeout: 5000 });
      const match = out.match(/V2Ray\s+(\d+\.\d+\.\d+)/);
      v2rayVersion = match ? match[1] : null;
    } catch { /* version check optional */ }
  }

  const v2ray = {
    available: !!v2rayPath,
    version: v2rayVersion,
    path: v2rayPath,
  };

  // WireGuard: our own comprehensive detection
  const wgPath = findWireGuard();
  const wireguard = {
    available: !!wgPath,
    path: wgPath,
    requiresAdmin: true,
  };

  // What this environment can do
  const capabilities = [];
  if (v2ray.available) capabilities.push('v2ray');
  if (wireguard.available && IS_ADMIN) capabilities.push('wireguard');
  if (wireguard.available && !IS_ADMIN) capabilities.push('wireguard-needs-admin');

  // What we recommend installing
  const recommended = [];
  if (!v2ray.available) recommended.push('v2ray — run: node setup.js');
  if (!wireguard.available && os === 'windows') {
    recommended.push('wireguard — run setup.js as admin for auto-install');
  }
  if (!wireguard.available && os === 'macos') {
    recommended.push('wireguard — run: brew install wireguard-tools');
  }
  if (!wireguard.available && os === 'linux') {
    recommended.push('wireguard — run: sudo apt install wireguard-tools');
  }
  if (wireguard.available && !IS_ADMIN) {
    recommended.push('run as admin to use WireGuard nodes (faster, more reliable)');
  }

  return {
    os,
    arch: process.arch,
    platform: `${os}-${process.arch}`,
    nodeVersion: process.versions.node,
    admin: IS_ADMIN,
    v2ray,
    wireguard,
    capabilities,
    recommended,
  };
}

// ─── setup() ─────────────────────────────────────────────────────────────────

/**
 * Full environment setup: check deps, install missing ones, report status.
 * Runs preflight checks that verify everything needed for a VPN connection.
 *
 * When no usable tunnel protocol is detected (no V2Ray, and no WireGuard
 * usable without admin), setup() auto-downloads V2Ray to the SDK's bin/
 * directory — no admin rights needed. Pass { autoInstall: false } to skip.
 *
 * Returns a FLAT structure — agents access .os, .v2ray, .wireguard directly.
 * No nested .environment wrapper to misread.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.autoInstall=true] - Download V2Ray when no usable tunnel binary exists
 * @returns {Promise<{
 *   ready: boolean,
 *   os: string,
 *   arch: string,
 *   platform: string,
 *   nodeVersion: string,
 *   admin: boolean,
 *   v2ray: boolean,
 *   v2rayVersion: string|null,
 *   v2rayPath: string|null,
 *   wireguard: boolean,
 *   wireguardPath: string|null,
 *   installed: boolean,
 *   capabilities: string[],
 *   recommended: string[],
 *   preflight: object|null,
 *   issues: string[],
 * }>}
 */
export async function setup(opts = {}) {
  const autoInstall = opts.autoInstall !== false;
  let env = getEnvironment();
  const issues = [];
  let installed = false;

  // Auto-install V2Ray when nothing usable is present. 'wireguard' only
  // appears in capabilities when the binary exists AND we have admin — a
  // non-admin WireGuard-only machine still cannot connect, so V2Ray
  // (which needs no admin) is downloaded for that case too.
  if (autoInstall && !env.v2ray.available && !env.capabilities.includes('wireguard')) {
    try {
      await installV2Ray();
      env = getEnvironment(); // re-detect — bin/ now holds v2ray + geoip/geosite
      installed = env.v2ray.available;
      if (!installed) {
        issues.push('V2Ray download completed but binary still not detected — check SDK bin/ directory permissions');
      }
    } catch (err) {
      issues.push(`V2Ray auto-install failed: ${err.message}`);
    }
  }

  // Run preflight checks — pass already-detected V2Ray path to avoid contradiction (BUG-1 fix)
  let preflightResult = null;
  try {
    const preflightOpts = {};
    if (env.v2ray?.path) preflightOpts.v2rayExePath = env.v2ray.path;
    preflightResult = await preflight(preflightOpts);
  } catch (err) {
    issues.push(`Preflight failed: ${err.message}`);
  }

  // Check critical requirements
  const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
  if (nodeMajor < 20) {
    issues.push(`Node.js ${process.versions.node} too old — need >= 20`);
  }

  if (!env.v2ray.available && !env.wireguard.available) {
    issues.push('No tunnel protocol available — install V2Ray or WireGuard (re-run setup() or: node node_modules/blue-js-sdk/setup.js)');
  }

  if (env.v2ray.available && env.v2ray.version && env.v2ray.version !== V2RAY_VERSION) {
    issues.push(`V2Ray version ${env.v2ray.version} — need exactly ${V2RAY_VERSION} (5.44.1+ has bugs)`);
  }

  const ready = issues.length === 0 && env.capabilities.length > 0;

  // Flat return — agent accesses .os, .v2ray, .admin directly
  return {
    ready,
    os: env.os,
    arch: env.arch,
    platform: env.platform,
    nodeVersion: env.nodeVersion,
    admin: env.admin,
    v2ray: env.v2ray.available,
    v2rayVersion: env.v2ray.version,
    v2rayPath: env.v2ray.path,
    wireguard: env.wireguard.available,
    wireguardPath: env.wireguard.path,
    installed,
    capabilities: env.capabilities,
    recommended: env.recommended,
    preflight: preflightResult,
    issues,
    // Backward compat — keep nested .environment for existing consumers
    environment: env,
  };
}
