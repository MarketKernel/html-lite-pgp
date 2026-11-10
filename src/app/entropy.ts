// The randomness the page works with (Task.md §4): the system generator, or the mouse.
//
// For a new key the user picks the source in the new-key dialog; for messages it is a setting.
// In mouse mode a window asks for movement until the pool has 256 credited events over two
// seconds; after that the page keeps feeding the pool with the pointer's movements (never
// with keys, which could be a passphrase being typed) for as long as it is open.

import { t } from '../core/i18n.ts';
import { EntropyPool, hardwareAvailable, hardwareRandom, mouseRandom } from '../core/crypto/random.ts';
import type { RandomSource } from '../core/crypto/random.ts';
import { app } from './state.ts';
import { dialog, h } from './ui.ts';

const sessionPool = new EntropyPool();
let following = false;
let hardware: RandomSource | null = null;
let mouse: RandomSource | null = null;

function pointer(pool: EntropyPool, event: PointerEvent): boolean {
  // Events a script made up are not movements of a hand.
  if (!event.isTrusted) return false;
  return pool.addPointer(event.clientX, event.clientY, event.timeStamp, [event.movementX, event.movementY, event.pressure, event.pointerType.length, performance.now()]);
}

/** Feeds the session pool with every movement over the page, from now on. */
function follow(): void {
  if (following) return;
  following = true;
  document.addEventListener('pointermove', (event) => void pointer(sessionPool, event), { passive: true });
}

/** The window that asks for movement. True when the pool is ready, false if closed. */
export async function collectMouse(pool: EntropyPool, title: string): Promise<boolean> {
  if (pool.ready) return true;
  const bar = h('span', { class: 'entropy-fill' });
  const percent = h('span', { class: 'entropy-percent', text: '0%' });
  const area = h(
    'div',
    { class: 'entropy-area', tabindex: '0', 'data-entropy-area': '' },
    h('span', { class: 'entropy-hint', text: t('entropy', 'Move the mouse here, or slide a finger — or type anything on the keyboard') }),
  );
  const meter = h('div', { class: 'entropy-meter', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100' }, bar);
  const update = () => {
    const p = Math.floor(pool.progress * 100);
    bar.style.width = `${p}%`;
    percent.textContent = `${p}%`;
    meter.setAttribute('aria-valuenow', String(p));
    if (pool.ready) {
      area.classList.add('entropy-area--done');
      area.querySelector('.entropy-hint')!.textContent = t('entropy', 'Enough. Thank you.');
      confirmButton()?.removeAttribute('disabled');
      // Closes by itself a moment later: nothing else to do here.
      window.setTimeout(() => confirmButton()?.click(), 400);
    }
  };
  const onMove = (event: PointerEvent) => {
    if (pointer(pool, event)) update();
  };
  const onKey = (event: KeyboardEvent) => {
    if (!event.isTrusted || event.repeat) return;
    if (pool.addKey(event.timeStamp, [performance.now()])) update();
  };
  area.addEventListener('pointermove', onMove);
  area.addEventListener('keydown', onKey);
  const confirmButton = () => area.closest('form')?.querySelector<HTMLButtonElement>('button[type=submit]');
  const ok = dialog({
    title,
    body: [
      h('p', { class: 'dialog-text', text: t('entropy', 'The random numbers come from your movements: each one counts for a little, and many are needed.') }),
      area,
      h('div', { class: 'entropy-row' }, meter, percent),
    ],
    confirm: t('entropy', 'Continue'),
    focus: area,
    submit: () => (pool.ready ? null : t('entropy', 'A little more movement is needed.')),
  });
  confirmButton()?.setAttribute('disabled', '');
  update();
  return ok;
}

export const hardwareReady = (): boolean => hardwareAvailable();

/** The generator for a new key, from the source the user chose. Null if they gave up. */
export async function keyRandom(source: 'hardware' | 'mouse'): Promise<RandomSource | null> {
  if (source === 'hardware') return hardwareRandom();
  const pool = new EntropyPool();
  if (!(await collectMouse(pool, t('entropy', 'Randomness for your new key')))) return null;
  return mouseRandom(pool);
}

/** The generator for messages, by the setting: the system's, or the mouse pool of this session. */
export async function messageRandom(): Promise<RandomSource | null> {
  if (app.settings.messageRandom === 'hardware' && hardwareAvailable()) {
    hardware ??= hardwareRandom();
    return hardware;
  }
  follow();
  if (!mouse) {
    if (!(await collectMouse(sessionPool, t('entropy', 'Randomness for this session')))) return null;
    mouse = mouseRandom(sessionPool);
  }
  return mouse;
}
