// Cross-platform WireGuard tunnel management
// Windows: wireguard.exe /installtunnelservice (requires admin OR elevation)
// Linux/macOS: wg-quick up/down (requires root/sudo)

import { execSync, execFileSync, spawnSync } from 'child_process';
import { existsSync, writeFileSync, unlinkSync, mkdirSync, statSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import os from 'os';
import { sleep } from './defaults.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Admin detection ──────────────────────────────────────────────────────────
function checkIsAdmin() {
  if (process.platform === 'win32') {
    try {
      // "net session" works on all Windows locales (unlike "whoami /groups" which depends on group name language)
      execSync('net session', { stdio: 'ignore', timeout: 3000 });
      return true;
    } catch {
      // Fallback: fsutil requires admin — works on non-English Windows too
      try {
        execSync('fsutil dirty query %systemdrive%', { stdio: 'ignore', timeout: 3000 });
        return true;
      } catch {
        return false;
      }
    }
  }
  // Linux/macOS: root = UID 0
  try {
    return process.getuid() === 0;
  } catch {
    return false;
  }
}

export const IS_ADMIN = checkIsAdmin();

// ─── WireGuard binary detection ───────────────────────────────────────────────
const WG_PATHS = [
  'C:\\Program Files\\WireGuard\\wireguard.exe',
  'C:\\Program Files (x86)\\WireGuard\\wireguard.exe',
  process.env.WIREGUARD_PATH || '',
].filter(Boolean);

function findWireGuardExe() {
  for (const p of WG_PATHS) {
    if (existsSync(p)) return p;
  }
  try {
    const result = execSync('where wireguard.exe', { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (result) return result.split('\n')[0].trim();
  } catch {}
  return null;
}

function findWgQuick() {
  // wg-quick has no --version flag. Use `which` (Unix) or `where` (Windows) to find it.
  try {
    const cmd = process.platform === 'win32' ? 'where wg-quick' : 'which wg-quick';
    const result = execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
    if (result) return result.split('\n')[0].trim();
  } catch {}
  // Also check common Linux paths directly
  const paths = ['/usr/bin/wg-quick', '/usr/local/bin/wg-quick', '/usr/sbin/wg-quick'];
  for (const p of paths) {
    if (existsSync(p)) return p;
  }
  return null;
}

export const WG_EXE   = findWireGuardExe();
export const WG_QUICK = findWgQuick();
export const WG_AVAILABLE = !!(WG_EXE || WG_QUICK);

let activeTunnelName = null;
let activeTunnelConf = null;
let tunnelInstalledAt = 0;  // timestamp when tunnel was installed

// ─── Emergency cleanup (exported for process exit handlers) ──────────────────
/**
 * Force-kill ALL WireGuard tunnels matching "wgsent*".
 * Safe to call multiple times. Does NOT throw.
 * Uses sync APIs only (safe in process exit handlers).
 */
export function emergencyCleanupSync() {
  // NOTE: Empty catches in this function are intentional.
  // This runs in process exit handlers where console output is unreliable.
  // Best-effort cleanup — each step must not block subsequent steps.

  // Windows: use wireguard.exe /uninstalltunnelservice + sc query
  if (WG_EXE && process.platform === 'win32') {
    for (const name of ['wgsent0', activeTunnelName].filter(Boolean)) {
      try {
        execFileSync(WG_EXE, ['/uninstalltunnelservice', name], { timeout: 10_000, stdio: 'pipe' });
      } catch {} // service may not exist
    }
    try {
      const services = execFileSync('sc', ['query', 'type=', 'service', 'state=', 'all'], { encoding: 'utf8', timeout: 5000 });
      const matches = services.match(/WireGuardTunnel\$wgsent\S*/g) || [];
      for (const svc of matches) {
        try { execFileSync('sc', ['stop', svc], { timeout: 5000, stdio: 'pipe' }); } catch {} // may already be stopped
        try { execFileSync('sc', ['delete', svc], { timeout: 5000, stdio: 'pipe' }); } catch {} // may already be deleted
      }
    } catch {} // sc query may fail — no services installed
  }

  // Linux/macOS: tear down known tunnel configs (and any wedged kernel interface)
  if (WG_QUICK && process.platform !== 'win32') {
    for (const name of ['wgsent0', activeTunnelName].filter(Boolean)) {
      const confPath = activeTunnelConf || `${os.tmpdir()}/sentinel-wg/${name}.conf`;
      teardownLinuxInterface(name, confPath);
    }
  }

  activeTunnelName = null;
  activeTunnelConf = null;
  tunnelInstalledAt = 0;
}

/**
 * Check if a tunnel is currently active.
 * Returns { active, name, uptimeMs } or { active: false }.
 * Does NOT kill the tunnel — tunnels stay up until explicitly disconnected.
 */
export function watchdogCheck() {
  if (!activeTunnelName || tunnelInstalledAt === 0) return { active: false };
  return { active: true, name: activeTunnelName, uptimeMs: Date.now() - tunnelInstalledAt };
}

// ─── Elevated WireGuard runner ────────────────────────────────────────────────
/**
 * Run a WireGuard command, elevating via PowerShell if not already admin.
 * When already admin: direct execFileSync.
 * When not admin: Start-Process -Verb RunAs -Wait (pops UAC once per call).
 */
function runWgCommand(args, timeoutMs = 30_000) {
  if (!WG_EXE) throw new Error('WireGuard not found');

  if (IS_ADMIN) {
    // Already elevated — run directly
    execFileSync(WG_EXE, args, { timeout: timeoutMs, stdio: 'pipe' });
    return;
  }

  // Not admin — elevate via PowerShell Start-Process -Verb RunAs
  // This pops a one-time UAC dialog per tunnel operation.
  const argStr = args.map(a => `'${a.replace(/'/g, "''")}'`).join(',');
  const ps = `Start-Process -FilePath '${WG_EXE.replace(/'/g, "''")}' -ArgumentList ${argStr} -Verb RunAs -Wait -WindowStyle Hidden`;
  const result = spawnSync('powershell', ['-NoProfile', '-Command', ps], {
    timeout: timeoutMs + 5000,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    const msg = (result.stderr || result.stdout || '').trim();
    throw new Error(`WireGuard elevated run failed: ${msg || `exit code ${result.status}`}`);
  }
}

// ─── Linux stale-interface teardown ───────────────────────────────────────────
/**
 * Best-effort removal of a leftover WireGuard interface on Linux/macOS.
 * Tries, in order: wg-quick down by conf path, wg-quick down by bare name, then a
 * raw `ip link delete` to clear a wedged kernel interface that wg-quick can't see.
 * Each step is independent and must not block the next — a no-op is expected when
 * there is nothing to remove. Does NOT throw.
 *
 * Why all three: a clean run is removed by wg-quick. But a crashed run leaves the
 * interface up with its config in a TEMP dir; `wg-quick down <name>` looks for
 * /etc/wireguard/<name>.conf (absent) and fails, so the interface survives and the
 * next `wg-quick up` dies with "<name> already exists". Passing the real conf path
 * fixes that; the `ip link delete` fallback handles the case where even the temp
 * conf is gone but the kernel interface lingers.
 */
function teardownLinuxInterface(name, confPath) {
  if (!WG_QUICK) return;
  // 1. By the actual conf path (covers temp-dir configs from a crashed run).
  if (confPath && existsSync(confPath)) {
    try { execFileSync(WG_QUICK, ['down', confPath], { timeout: 10_000, stdio: 'pipe' }); } catch {} // conf may not be up
  }
  // 2. By bare interface name (covers configs installed under /etc/wireguard).
  try { execFileSync(WG_QUICK, ['down', name], { timeout: 10_000, stdio: 'pipe' }); } catch {} // interface may not exist
  // 3. Raw kernel interface delete — last resort for an interface wg-quick can't map
  //    back to a config (e.g. temp conf already deleted). `ip` is Linux-only.
  if (process.platform === 'linux') {
    try { execFileSync('ip', ['link', 'delete', 'dev', name], { timeout: 5_000, stdio: 'pipe' }); } catch {} // interface may not exist
  }
}

// ─── Install tunnel ───────────────────────────────────────────────────────────
/**
 * Install and activate a WireGuard tunnel.
 * confPath: absolute path to the .conf file.
 * NOTE: activeTunnelName is set ONLY after successful install so that
 * a failed install doesn't cause uninstallWgTunnel to attempt removal of
 * a service that was never registered (avoids "service does not exist" error).
 */
export async function installWgTunnel(confPath) {
  const name = path.basename(confPath, '.conf');  // e.g. "wgsent0"

  if (WG_EXE) {
    // Always force-remove any leftover tunnel with this name before installing
    try { runWgCommand(['/uninstalltunnelservice', name], 10_000); } catch { }
    await sleep(1000);

    runWgCommand(['/installtunnelservice', confPath], 30_000);
    activeTunnelConf = confPath;
    activeTunnelName = name;
    tunnelInstalledAt = Date.now();

    // VERIFY the service actually started — don't return success on silent failure.
    // WireGuard /installtunnelservice can silently fail if:
    //   - Config path is in user temp (SYSTEM account can't read it)
    //   - Service registration fails (duplicate name, permission issue)
    //   - Config syntax error (WireGuard rejects it quietly)
    const verified = await verifyTunnelRunning(name);
    if (!verified) {
      // Cleanup the failed state
      try { runWgCommand(['/uninstalltunnelservice', name], 10_000); } catch {}
      activeTunnelConf = null;
      activeTunnelName = null;
      tunnelInstalledAt = 0;
      throw new Error(
        `WireGuard tunnel '${name}' failed to start. The service was registered but never reached RUNNING state. ` +
        `This usually means the config file path (${confPath}) is not readable by the SYSTEM account. ` +
        `Ensure the app is running as Administrator.`
      );
    }

    return activeTunnelName;
  } else if (WG_QUICK) {
    // Force-remove any leftover interface with this name before installing, otherwise
    // `wg-quick up` aborts with "wgsent0 already exists" (Linux full-tunnel regression).
    // A crashed/killed previous run leaves the kernel interface AND a temp-dir conf behind;
    // `wg-quick down <name>` alone does NOT cover the temp-dir case because it resolves the
    // bare name against /etc/wireguard/<name>.conf, which is empty here. Tear down by the
    // actual conf path first, then by name, then delete the raw kernel interface as a
    // last resort so a wedged interface from a prior crash can never block reconnect.
    teardownLinuxInterface(name, confPath);
    await sleep(500);
    execFileSync(WG_QUICK, ['up', confPath], { timeout: 30_000, stdio: 'inherit' });
    activeTunnelConf = confPath;
    activeTunnelName = name;
    tunnelInstalledAt = Date.now();
    // Verify wg-quick created the interface
    await sleep(1000);
    try {
      const wgOut = execFileSync('wg', ['show'], { encoding: 'utf8', timeout: 5000, stdio: 'pipe' });
      if (!wgOut.includes(name)) {
        throw new Error(`WireGuard interface '${name}' not found after wg-quick up. Check permissions (sudo may be required).`);
      }
    } catch (err) {
      if (err.message.includes('not found')) throw err;
      // wg command not available — skip verification
    }
    return activeTunnelName;
  } else {
    const installHint = process.platform === 'win32'
      ? 'Install from https://download.wireguard.com/windows-client/wireguard-installer.exe'
      : process.platform === 'darwin'
        ? 'Install: brew install wireguard-tools'
        : 'Install: sudo apt install wireguard (or equivalent)';
    throw new Error(`WireGuard not found. ${installHint}`);
  }
}

/**
 * Verify a WireGuard tunnel service is actually running.
 * Polls `sc query` over up to 15 seconds with 500ms intervals.
 * Distinguishes START_PENDING (keep waiting) from STOPPED (give up).
 * Returns true if the service reaches RUNNING state.
 */
async function verifyTunnelRunning(tunnelName, maxWaitMs = 15000) {
  const serviceName = `WireGuardTunnel$${tunnelName}`;
  const start = Date.now();
  const pollInterval = 500;

  while (Date.now() - start < maxWaitMs) {
    try {
      const out = execFileSync('sc', ['query', serviceName], { encoding: 'utf8', timeout: 3000, stdio: 'pipe' });
      if (out.includes('RUNNING')) return true;
      // Service explicitly stopped or failed — don't keep waiting
      if (out.includes('STOPPED') || out.includes('STOP_PENDING')) return false;
      // START_PENDING — keep polling (normal during WireGuard driver init)
    } catch {
      // Service not registered in SCM yet — keep waiting
    }
    await sleep(pollInterval);
  }
  return false;
}

// ─── Uninstall tunnel ─────────────────────────────────────────────────────────
export async function uninstallWgTunnel(tunnelName) {
  const name = tunnelName || activeTunnelName;
  if (!name) return;

  try {
    if (WG_EXE) {
      runWgCommand(['/uninstalltunnelservice', name], 15_000);
    } else if (WG_QUICK) {
      // Use conf path if available, otherwise fall back to interface name
      const target = activeTunnelConf || name;
      execFileSync(WG_QUICK, ['down', target], { timeout: 15_000, stdio: 'pipe' });
    }
  } catch (err) {
    console.error(`  [WG] Disconnect warning: ${err.message}`);
  }

  try {
    if (activeTunnelConf && existsSync(activeTunnelConf)) {
      // Scrub private key before deletion — if unlink fails (file locked),
      // at least the key bytes are zeroed on disk.
      try {
        const size = statSync(activeTunnelConf).size;
        writeFileSync(activeTunnelConf, Buffer.alloc(size, 0));
      } catch { /* scrub best-effort */ }
      unlinkSync(activeTunnelConf);
    }
  } catch { /* cleanup best-effort */ }
  activeTunnelName = null;
  activeTunnelConf = null;
  tunnelInstalledAt = 0;
}

// ─── Legacy compat (still used by old connectWireGuard callers) ───────────────
export async function connectWireGuard(wgInstance) {
  const tmpDir = path.join(os.tmpdir(), 'sentinel-wg');
  mkdirSync(tmpDir, { recursive: true });
  const confPath = path.join(tmpDir, 'wgsent0.conf');
  wgInstance.writeConfig(confPath);
  return installWgTunnel(confPath);
}

export async function disconnectWireGuard() {
  return uninstallWgTunnel(activeTunnelName);
}

