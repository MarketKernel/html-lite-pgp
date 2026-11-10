// Dialogs, menus, toasts and the secret field — enough to avoid the browser's own prompts.
// After html-pgp's ui.ts; the icons are built element by element: the page's policy (Trusted
// Types) refuses HTML from strings, and rightly.

import { t } from '../core/i18n.ts';
import { closed, isNarrow, opened } from './screens.ts';

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, string>> = {},
  ...children: (Node | string | null | undefined | false)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
}

const SVG = 'http://www.w3.org/2000/svg';

/**
 * One SVG icon from a list of shapes written as markup, stroked with the current colour. The
 * markup is ours (ICONS below) and is read shape by shape into elements — never as HTML.
 */
export function icon(shapes: string): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  for (const m of shapes.matchAll(/<(\w+)((?:\s+[\w-]+="[^"]*")*)\s*\/>/g)) {
    const node = document.createElementNS(SVG, m[1]);
    for (const a of m[2].matchAll(/([\w-]+)="([^"]*)"/g)) node.setAttribute(a[1], a[2]);
    svg.append(node);
  }
  return svg;
}

export const ICONS = {
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M14 9l2 2"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  unlock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  import: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  export: '<path d="M12 15V4M7 9l5-5 5 5M5 20h14"/>',
  certify: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
  more: '<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  notepad: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M9 13h6M9 17h4M14 3v5h5"/>',
  keys: '<circle cx="7.5" cy="15.5" r="3.5"/><path d="M10 13l7-7M15 8l2 2M13 10l1.5 1.5"/><path d="M14 20h6M17 17v6" transform="translate(0 -3)"/>',
  settings:
    '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 5.1A10.4 10.4 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6A16.8 16.8 0 0 0 2 12s3.6 7 10 7a9.8 9.8 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  back: '<path d="M15 18l-6-6 6-6"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  warning: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
  cross: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  clipboard: '<rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3h6v1M9 9h6M9 13h6M9 17h4"/>',
  save: '<path d="M5 4h11l4 4v12H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z"/><path d="M8 4v5h7M8 20v-6h8v6"/>',
  signature: '<path d="M3 17c3-1 4-9 6-9s-1 8 1 8 3-5 5-5 1 4 3 4 2-1 3-2"/><path d="M3 21h18"/>',
  envelope: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  open: '<path d="M4 12a8 8 0 0 1 14-5.3M20 12a8 8 0 0 1-14 5.3"/><path d="M18 3v4h-4M6 21v-4h4"/>',
};

/* ------------------------------------------------------------------ *
 * Secret inputs
 *
 * On macOS a browser that decides a field holds a password turns on Secure
 * Input, and the system then forces an ASCII keyboard layout: a Cyrillic
 * (or any non-Latin) passphrase cannot be typed at all. Chrome decides so not
 * only for type=password but also, by heuristics, for text fields styled
 * with -webkit-text-security or holding a value made of dots — and once it
 * has, the field stays a "password" for good.
 *
 * So a secret field gives the browser no such hint. It is a plain text input
 * that keeps the real value; the text itself is transparent, and a layer of
 * dots drawn over it shows its length. Both use a monospace font, so every
 * dot sits over its character and the caret lands where it should.
 * ------------------------------------------------------------------ */

const DOT = '•';
const syncs = new WeakMap<HTMLInputElement, () => void>();

/**
 * Hides the input's text without anything a browser reads as a password field.
 * Returns the layer of dots, which the caller puts right after the input, inside
 * a positioned parent. `data-secret` marks the input for good.
 */
export function maskInput(input: HTMLInputElement): HTMLElement {
  input.type = 'text';
  input.dataset['secret'] = '';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.setAttribute('autocapitalize', 'off');
  input.setAttribute('autocorrect', 'off');
  input.classList.add('secret-input', 'masked');

  const dots = h('span', { class: 'secret-dots' });
  const layer = h('span', { class: 'secret-layer', 'aria-hidden': 'true' }, dots);

  const sync = (): void => {
    const masked = input.classList.contains('masked');
    layer.hidden = !masked || !input.value;
    if (layer.hidden) return;
    dots.textContent = DOT.repeat(Array.from(input.value).length);
    // The layer covers exactly the input's text box, so the dots scroll with the text.
    const style = getComputedStyle(input);
    const padLeft = parseFloat(style.paddingLeft) + parseFloat(style.borderLeftWidth);
    const padRight = parseFloat(style.paddingRight) + parseFloat(style.borderRightWidth);
    layer.style.left = `${input.offsetLeft + padLeft}px`;
    layer.style.top = `${input.offsetTop}px`;
    layer.style.width = `${Math.max(0, input.offsetWidth - padLeft - padRight)}px`;
    layer.style.height = `${input.offsetHeight}px`;
    layer.style.font = style.font;
    layer.style.letterSpacing = style.letterSpacing;
    dots.style.transform = `translateX(${-input.scrollLeft}px)`;
  };
  syncs.set(input, sync);

  // While focused, the caret can scroll the text in ways no event reports; follow it per frame.
  let frame = 0;
  const follow = (): void => {
    sync();
    frame = requestAnimationFrame(follow);
  };
  input.addEventListener('focus', () => {
    cancelAnimationFrame(frame);
    follow();
  });
  input.addEventListener('blur', () => {
    cancelAnimationFrame(frame);
    sync();
  });
  input.addEventListener('input', sync);
  new ResizeObserver(sync).observe(input);

  // A masked field must not hand its text out through copy or cut, as type=password does not.
  const guard = (event: Event): void => {
    if (input.classList.contains('masked')) event.preventDefault();
  };
  input.addEventListener('copy', guard);
  input.addEventListener('cut', guard);
  input.addEventListener('dragstart', guard);
  return layer;
}

export function setRevealed(input: HTMLInputElement, revealed: boolean): void {
  input.classList.toggle('masked', !revealed);
  syncs.get(input)?.();
}

/** The alphabet of the last letter in `text` — shows the layout a masked field is being typed in. */
export function layoutOf(text: string): string | null {
  const letters = text.match(/\p{L}/gu);
  const last = letters?.[letters.length - 1];
  if (!last) return null;
  if (/\p{Script=Cyrillic}/u.test(last)) return 'КИР';
  if (/\p{Script=Latin}/u.test(last)) return 'LAT';
  if (/\p{Script=Greek}/u.test(last)) return 'ΕΛΛ';
  if (/\p{Script=Arabic}/u.test(last)) return 'عر';
  return null;
}

/** A masked input with a layout badge and a show/hide button. */
export function secretField(input: HTMLInputElement): HTMLElement {
  const layer = maskInput(input);
  const badge = h('span', { class: 'layout-badge', 'aria-live': 'polite' });
  const update = (): void => {
    const layout = layoutOf(input.value);
    badge.hidden = !layout;
    badge.textContent = layout ?? '';
  };
  input.addEventListener('input', update);
  update();
  const reveal = h('button', { type: 'button', class: 'icon-button icon-button--small', title: t('passphrase', 'Show'), 'aria-label': t('passphrase', 'Show') }, icon(ICONS.eye));
  reveal.addEventListener('click', () => {
    const shown = input.classList.contains('masked');
    setRevealed(input, shown);
    reveal.title = shown ? t('passphrase', 'Hide') : t('passphrase', 'Show');
    reveal.replaceChildren(icon(shown ? ICONS.eyeOff : ICONS.eye));
    input.focus();
  });
  return h('span', { class: 'secret-field' }, input, layer, badge, reveal);
}

/* ------------------------------------------------------------------ *
 * Dialogs
 *
 * Each dialog is its own overlay, so one can open over another — a passphrase
 * asked for while the certify dialog waits. Escape and a click beside it close
 * the one on top.
 * ------------------------------------------------------------------ */

export interface DialogOptions {
  title: string;
  /** What the dialog shows between its title and its buttons. */
  body?: (Node | string | null | false)[];
  /** The confirming button; without one there is only Close. */
  confirm?: string;
  /** null — no cancel button: the dialog only says something. */
  cancel?: string | null;
  danger?: boolean;
  wide?: boolean;
  /**
   * Runs on confirm, with the buttons disabled. An error to show keeps the
   * dialog open; anything else closes it.
   */
  submit?: () => Promise<string | null | void> | string | null | void;
  /** Focused when the dialog opens; the first field otherwise. */
  focus?: HTMLElement | null;
}

/** The dialog on top, the one Escape closes. */
const topOverlay = (): Element | undefined => [...document.querySelectorAll('.overlay')].at(-1);

/** True when confirmed, false when closed any other way. */
export function dialog(options: DialogOptions): Promise<boolean> {
  const overlay = h('div', { class: 'overlay' });
  const box = h('form', { class: `dialog${options.wide ? ' dialog--wide' : ''}`, role: 'dialog', 'aria-modal': 'true' });
  // The dialog checks its fields itself, in words of its own: the browser's bubble would stop the submit silently.
  box.noValidate = true;
  const title = h('h2', { text: options.title, id: `dialog-${Date.now()}` });
  box.setAttribute('aria-labelledby', title.id);
  const content = h('div', { class: 'dialog-body' });
  for (const part of options.body ?? []) if (part) content.append(typeof part === 'string' ? h('p', { class: 'dialog-text', text: part }) : part);
  const error = h('p', { class: 'dialog-error', 'aria-live': 'polite' });
  const row = h('div', { class: 'dialog-row' });
  const cancelLabel = options.cancel === undefined ? (options.confirm ? t('dialog', 'Cancel') : t('dialog', 'Close')) : options.cancel;
  const cancel = cancelLabel ? h('button', { type: 'button', class: 'button button--ghost', 'data-cancel': '', text: cancelLabel }) : null;
  const confirm = options.confirm ? h('button', { type: 'submit', class: `button ${options.danger ? 'button--danger' : 'button--primary'}`, text: options.confirm }) : null;
  if (cancel) row.append(cancel);
  if (confirm) row.append(confirm);
  box.append(title, content, error, row);
  overlay.append(box);
  document.body.append(overlay);
  opened('dialog');

  const first = options.focus ?? box.querySelector<HTMLElement>('input:not([type=checkbox]):not([type=radio]), textarea, select') ?? confirm ?? cancel;
  first?.focus();

  return new Promise((resolve) => {
    let busy = false;
    const close = (result: boolean): void => {
      overlay.remove();
      document.removeEventListener('keydown', onKey, true);
      closed();
      resolve(result);
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key !== 'Escape' || topOverlay() !== overlay) return;
      if (document.querySelector('.context-menu')) return;
      event.preventDefault();
      event.stopPropagation();
      if (!busy) close(false);
    };
    document.addEventListener('keydown', onKey, true);
    overlay.addEventListener('dismiss', () => {
      if (!busy) close(false);
    });
    cancel?.addEventListener('click', () => {
      if (!busy) close(false);
    });
    overlay.addEventListener('mousedown', (event) => {
      if (event.target === overlay && !busy) close(false);
    });
    box.addEventListener('submit', (event) => {
      event.preventDefault();
      if (busy || !confirm) return;
      error.textContent = '';
      const result = options.submit?.();
      if (!(result instanceof Promise)) {
        if (result) error.textContent = result;
        else close(true);
        return;
      }
      busy = true;
      box.classList.add('dialog--busy');
      for (const button of row.querySelectorAll('button')) button.disabled = true;
      result
        .then(
          (problem) => problem ?? null,
          (failure: unknown) => (failure instanceof Error ? failure.message : String(failure)),
        )
        .then((problem) => {
          busy = false;
          box.classList.remove('dialog--busy');
          for (const button of row.querySelectorAll('button')) button.disabled = false;
          if (problem) error.textContent = problem;
          else close(true);
        });
    });
  });
}

/** A dialog that only tells something. */
export async function inform(title: string, ...body: (Node | string | null | false)[]): Promise<void> {
  await dialog({ title, body, cancel: t('dialog', 'Close') });
}

export async function confirmAsk(title: string, message: string | (Node | string)[], confirm: string, danger = true): Promise<boolean> {
  return dialog({ title, body: typeof message === 'string' ? [message] : message, confirm, danger });
}

/* ------------------------------------------------------------------ *
 * Form fields for dialogs
 * ------------------------------------------------------------------ */

export function field(label: string, control: HTMLElement, hint?: string): HTMLLabelElement {
  const node = h('label', { class: 'dialog-label' }, h('span', { class: 'dialog-label-text', text: label }), control);
  if (hint) node.append(h('span', { class: 'dialog-hint', text: hint }));
  return node;
}

export function textInput(value = '', props: Partial<Record<string, string>> = {}): HTMLInputElement {
  const input = h('input', { class: 'dialog-input', type: 'text', autocomplete: 'off', spellcheck: 'false', ...props });
  input.value = value;
  return input;
}

export function secretInput(placeholder = ''): { input: HTMLInputElement; node: HTMLElement } {
  const input = h('input', { class: 'dialog-input', placeholder });
  return { input, node: secretField(input) };
}

export function checkbox(label: string, checked = false, hint?: string): { input: HTMLInputElement; node: HTMLLabelElement } {
  const input = h('input', { type: 'checkbox', class: 'dialog-check' });
  input.checked = checked;
  const node = h('label', { class: 'dialog-label dialog-label--check' }, input, h('span', { text: label }));
  if (hint) node.append(h('span', { class: 'dialog-hint', text: hint }));
  return { input, node };
}

export function select<T extends string>(choices: { value: T; label: string; group?: string }[], value: T): HTMLSelectElement {
  const node = h('select', { class: 'dialog-input dialog-select' });
  const groups = new Map<string, HTMLOptGroupElement>();
  for (const choice of choices) {
    const option = h('option', { value: choice.value, text: choice.label });
    if (choice.group) {
      let group = groups.get(choice.group);
      if (!group) {
        group = h('optgroup', { label: choice.group });
        groups.set(choice.group, group);
        node.append(group);
      }
      group.append(option);
    } else node.append(option);
  }
  node.value = value;
  return node;
}

/* ------------------------------------------------------------------ *
 * Menus
 * ------------------------------------------------------------------ */

export interface MenuItem {
  label: string;
  action: () => void;
  danger?: boolean;
  disabled?: boolean;
  /** A thin line above the item. */
  separated?: boolean;
  hint?: string;
}

/**
 * On a phone a menu is a sheet: pinned to the bottom, as wide as the screen,
 * over a dimmed page that closes it on a tap. Returns what undoes it.
 */
function asSheet(panel: HTMLElement, dismiss: () => void): () => void {
  panel.classList.add('context-menu--sheet');
  const backdrop = h('div', { class: 'sheet-backdrop' });
  backdrop.addEventListener('click', dismiss);
  panel.before(backdrop);
  opened('sheet');
  return () => {
    backdrop.remove();
    closed();
  };
}

export function menu(x: number, y: number, items: MenuItem[]): void {
  document.querySelector('.context-menu')?.dispatchEvent(new Event('dismiss'));
  const sheet = isNarrow();
  const list = h('div', { class: 'context-menu', role: 'menu' });
  for (const item of items) {
    if (item.separated) list.append(h('div', { class: 'context-sep' }));
    const button = h(
      'button',
      { type: 'button', role: 'menuitem', class: `context-item${item.danger ? ' context-item--danger' : ''}` },
      h('span', { text: item.label }),
      item.hint ? h('kbd', { text: item.hint }) : null,
    );
    button.disabled = Boolean(item.disabled);
    button.addEventListener('click', () => {
      dismiss();
      item.action();
    });
    list.append(button);
  }
  if (sheet) {
    const cancel = h('button', { type: 'button', class: 'context-item context-item--cancel', text: t('dialog', 'Cancel') });
    cancel.addEventListener('click', () => dismiss());
    list.append(h('div', { class: 'context-sep' }), cancel);
  }
  document.body.append(list);
  let unsheet: (() => void) | null = null;
  if (sheet) unsheet = asSheet(list, () => dismiss());
  else {
    const width = list.offsetWidth;
    const height = list.offsetHeight;
    const rtl = document.documentElement.dir === 'rtl';
    const left = rtl ? x - width : x;
    list.style.left = `${Math.max(8, Math.min(left, window.innerWidth - width - 8))}px`;
    list.style.top = `${Math.max(8, Math.min(y, window.innerHeight - height - 8))}px`;
  }
  (list.querySelector('button:not(:disabled)') as HTMLButtonElement | null)?.focus({ preventScroll: true });

  const onDown = (event: Event): void => {
    if (event.target instanceof Node && (list.contains(event.target) || (event.target as Element).classList?.contains('sheet-backdrop'))) return;
    dismiss();
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === 'Escape') {
      event.stopPropagation();
      dismiss();
      return;
    }
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    const buttons = [...list.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next = buttons[(at + (event.key === 'ArrowDown' ? 1 : buttons.length - 1)) % buttons.length];
    next?.focus();
  };
  let open = true;
  function dismiss(): void {
    if (!open) return;
    open = false;
    list.remove();
    unsheet?.();
    document.removeEventListener('mousedown', onDown, true);
    document.removeEventListener('keydown', onKey, true);
  }
  list.addEventListener('dismiss', dismiss);
  window.setTimeout(() => {
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
  });
}

export function menuAt(anchor: HTMLElement, items: MenuItem[]): void {
  const box = anchor.getBoundingClientRect();
  const rtl = document.documentElement.dir === 'rtl';
  menu(rtl ? box.right : box.left, box.bottom + 4, items);
}

/* ------------------------------------------------------------------ *
 * Toasts
 * ------------------------------------------------------------------ */

let toastTimer = 0;

export function toast(message: string, kind: 'info' | 'error' = 'info'): void {
  let box = document.querySelector<HTMLDivElement>('.toast');
  if (!box) {
    box = h('div', { class: 'toast', role: 'status' });
    document.body.append(box);
  }
  box.textContent = message;
  box.classList.toggle('toast--error', kind === 'error');
  box.classList.add('toast--shown');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => box?.classList.remove('toast--shown'), kind === 'error' ? 6000 : 2600);
}

/** A stable hue per text (FNV-1a), so a key keeps its colour between sessions. */
export function hue(text: string): number {
  let hash = 0x811c9dc5;
  for (const char of text) hash = Math.imul(hash ^ (char.codePointAt(0) ?? 0), 0x01000193) >>> 0;
  return hash % 360;
}

/** Initials for a key's avatar: of the name, or of the address. */
export function initials(name: string, email: string): string {
  const words = (name || email.split('@')[0] || '?').split(/[\s._-]+/).filter(Boolean);
  const letters = words.length > 1 ? [words[0], words[words.length - 1]] : [words[0] ?? '?'];
  return letters.map((word) => Array.from(word ?? '')[0] ?? '').join('').toUpperCase();
}

export function avatar(name: string, email: string, seed: string, size: 'small' | 'large' = 'small'): HTMLElement {
  const node = h('span', { class: `avatar avatar--${size}`, 'aria-hidden': 'true', text: initials(name, email) });
  node.style.setProperty('--hue', String(hue(seed)));
  return node;
}
