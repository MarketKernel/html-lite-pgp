// Runs the local GnuPG in a throwaway home directory, for the tests that check what we write
// against GnuPG itself. Never the user's own ~/.gnupg. Without gpg the tests say so and pass.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const GPG = (() => {
  try {
    execFileSync('gpg', ['--version'], { stdio: 'ignore' });
    return 'gpg';
  } catch {
    return null;
  }
})();

export interface Gnupg {
  home: string;
  /** Runs gpg with these arguments; returns stdout, throws with stderr on failure. */
  run(args: string[], input?: Uint8Array | string): Buffer;
  /** The same, but returns the exit status and both outputs instead of throwing. */
  attempt(args: string[], input?: Uint8Array | string): { status: number; stdout: Buffer; stderr: string };
}

export function withGnupg<T>(body: (g: Gnupg) => T): T {
  // GnuPG's agent puts its sockets in the home directory: the path must stay short.
  const base = tmpdir().length > 60 ? '/tmp' : tmpdir();
  const home = mkdtempSync(join(base, 'hsp-'));
  const attempt = (args: string[], input?: Uint8Array | string) => {
    const r = spawnSync('gpg', ['--homedir', home, '--batch', '--yes', '--pinentry-mode', 'loopback', '--trust-model', 'always', ...args], { input, maxBuffer: 1 << 28 });
    return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr.toString() };
  };
  const run = (args: string[], input?: Uint8Array | string) => {
    const r = attempt(args, input);
    if (r.status !== 0) throw new Error(`gpg ${args.join(' ')}\n${r.stderr}`);
    return r.stdout;
  };
  try {
    return body({ home, run, attempt });
  } finally {
    spawnSync('gpgconf', ['--homedir', home, '--kill', 'all']);
    rmSync(home, { recursive: true, force: true });
  }
}
