// The keys view: the keyring as a list to search and filter, with the selected key's details
// beside it — or, on a phone, on a screen of their own. (After html-pgp.)

import { t, tn } from '../core/i18n.ts';
import { renderDetails } from './details.ts';
import { deleteKeys, exportPublic, importFiles, importFromClipboard, importPasted, markAsVerified, newKeyPair, restoreFromPhrase, selection } from './keyactions.ts';
import { allViews, formatDate, keyIdLabel, label, validity } from './model.ts';
import type { KeyView } from './model.ts';
import { copyText } from './save.ts';
import { hideDetails, isNarrow, showDetails } from './screens.ts';
import type { KeyFilter } from './settings.ts';
import { app, onKeyringChange, saveState } from './state.ts';
import { avatar, h, icon, ICONS, menu, menuAt, toast } from './ui.ts';
import type { MenuItem } from './ui.ts';

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let selected = new Set<string>();
let focused: string | null = null;
let anchor: string | null = null;
let query = '';
let shown: KeyView[] = [];

const compact = (text: string): string => text.toLowerCase().replace(/\s+/g, '').replace(/^0x/, '');

function matches(v: KeyView, words: string[]): boolean {
  const haystack = [v.name, v.email, ...v.state.userIds.map((u) => u.text)].join(' ').toLowerCase();
  const ids = [v.fingerprint, ...v.entry.cert.subkeys.map((s) => Array.from(s.key.fingerprint, (b) => b.toString(16).padStart(2, '0')).join(''))].join(' ').toLowerCase();
  return words.every((word) => haystack.includes(word) || ids.includes(compact(word)));
}

function passes(v: KeyView, filter: KeyFilter): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'mine':
      return v.secret;
    case 'verified':
      return v.status === 'valid' && !v.secret && v.verified;
    case 'unverified':
      return v.status === 'valid' && !v.verified;
    case 'unusable':
      return v.status !== 'valid';
  }
}

const sortName = (v: KeyView): string => (v.name || v.email || v.keyId).toLocaleLowerCase();

function visible(): KeyView[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return allViews()
    .filter((v) => passes(v, app.settings.filter) && matches(v, words))
    .sort((a, b) => sortName(a).localeCompare(sortName(b)));
}

export function selectedViews(): KeyView[] {
  return allViews().filter((v) => selected.has(v.fingerprint));
}

function row(v: KeyView): HTMLElement {
  const valid = validity(v);
  return h(
    'div',
    {
      class: `key-row${selected.has(v.fingerprint) ? ' key-row--selected' : ''}${focused === v.fingerprint ? ' key-row--focused' : ''}${v.status !== 'valid' ? ' key-row--dim' : ''}`,
      role: 'row',
      id: `key-${v.fingerprint}`,
      'data-fpr': v.fingerprint,
      'aria-selected': String(selected.has(v.fingerprint)),
    },
    h(
      'span',
      { class: 'key-cell key-cell--name', role: 'gridcell' },
      avatar(v.name, v.email, v.fingerprint),
      h('span', { class: 'key-names' }, h('span', { class: 'key-name', text: v.name || v.email || keyIdLabel(v.keyId) }), h('span', { class: 'key-email', text: v.name ? v.email : '' })),
      v.secret ? h('span', { class: 'key-secret', title: t('keys', 'Your key pair: the secret key is here') }, icon(ICONS.key)) : null,
    ),
    h('span', { class: 'key-cell key-cell--email', role: 'gridcell', text: v.email }),
    h('span', { class: 'key-cell key-cell--status', role: 'gridcell' }, h('span', { class: `chip chip--${valid.tone}`, title: valid.hint, text: valid.label })),
    h('span', { class: 'key-cell key-cell--date', role: 'gridcell', text: formatDate(v.state.expires) }),
    h('span', { class: 'key-cell key-cell--id mono', role: 'gridcell', text: v.keyId.slice(-8) }),
  );
}

export function renderList(): void {
  shown = visible();
  const list = $('key-rows');
  list.replaceChildren(...shown.map(row));
  const total = app.keyring.size;
  // In container mode, before the container is open, its gate stands where the empty state would.
  $('keys-empty').hidden = total > 0 || document.body.classList.contains('container-gated');
  $('keys-table').hidden = total === 0;
  $('keys-none').hidden = total === 0 || shown.length > 0;
  $('nav-count').textContent = total ? String(total) : '';
  ($('export') as HTMLButtonElement).disabled = selected.size === 0;
  $('keys-count').textContent = shown.length === total ? tn('keys', '{count} key', '{count} keys', total) : t('keys', '{shown} of {total}', { shown: shown.length, total });
  renderSide();
}

function renderSide(): void {
  const details = $('details');
  const placeholder = $('details-placeholder');
  const views = selectedViews();
  document.body.classList.toggle('details-open', views.length > 0);
  if (views.length === 1) {
    placeholder.hidden = true;
    details.hidden = false;
    renderDetails(views[0], details);
    return;
  }
  if (views.length > 1) {
    placeholder.hidden = true;
    details.hidden = false;
    const exportButton = h('button', { type: 'button', class: 'button button--small' }, icon(ICONS.export), h('span', { text: t('keys', 'Export') }));
    exportButton.addEventListener('click', () => void exportPublic(views));
    const deleteButton = h('button', { type: 'button', class: 'button button--small button--danger-ghost' }, icon(ICONS.trash), h('span', { text: t('keys', 'Delete') }));
    deleteButton.addEventListener('click', () => void deleteKeys(views));
    details.replaceChildren(
      h(
        'div',
        { class: 'details-many' },
        h('h2', { text: tn('keys', '{count} key selected', '{count} keys selected', views.length) }),
        h('ul', { class: 'import-list' }, ...views.map((v) => h('li', {}, h('span', { text: label(v) }), h('span', { class: 'mono', text: keyIdLabel(v.keyId) })))),
        h('div', { class: 'details-actions' }, exportButton, deleteButton),
      ),
    );
    return;
  }
  details.hidden = true;
  details.replaceChildren();
  placeholder.hidden = false;
  hideDetails();
}

export function showKey(fingerprint: string): void {
  const v = allViews().find((x) => x.fingerprint === fingerprint);
  if (!v) return;
  if (!passes(v, app.settings.filter)) {
    app.settings.filter = 'all';
    ($('filter') as HTMLSelectElement).value = 'all';
    saveState();
  }
  selected = new Set([fingerprint]);
  focused = anchor = fingerprint;
  renderList();
  document.getElementById(`key-${fingerprint}`)?.scrollIntoView({ block: 'nearest' });
  showDetails();
}

function pick(fingerprint: string, event: { metaKey: boolean; ctrlKey: boolean; shiftKey: boolean }): void {
  const from = shown.findIndex((v) => v.fingerprint === anchor);
  if (event.shiftKey && from >= 0 && !isNarrow()) {
    const to = shown.findIndex((v) => v.fingerprint === fingerprint);
    const [a, b] = from < to ? [from, to] : [to, from];
    selected = new Set(shown.slice(a, b + 1).map((v) => v.fingerprint));
    focused = fingerprint;
    renderList();
    return;
  }
  if ((event.metaKey || event.ctrlKey) && !isNarrow()) {
    if (selected.has(fingerprint)) selected.delete(fingerprint);
    else selected.add(fingerprint);
    focused = anchor = fingerprint;
    renderList();
    return;
  }
  showKey(fingerprint);
}

function rowMenu(v: KeyView, x: number, y: number): void {
  if (!selected.has(v.fingerprint)) showKey(v.fingerprint);
  const views = selectedViews();
  const many = views.length > 1;
  const items: MenuItem[] = [
    { label: many ? t('keys', 'Export {count} public keys…', { count: views.length }) : t('keys', 'Export public key…'), action: () => void exportPublic(views) },
    { label: t('keys', 'Copy fingerprint'), disabled: many, action: () => void copyText(v.fingerprint).then(() => toast(t('keys', 'Fingerprint copied'))) },
    { label: t('keys', 'Mark as verified…'), disabled: many || v.secret || v.status !== 'valid', action: () => void markAsVerified(v) },
    { label: many ? t('keys', 'Delete {count} keys…', { count: views.length }) : t('keys', 'Delete…'), danger: true, separated: true, action: () => void deleteKeys(views) },
  ];
  menu(x, y, items);
}

function move(step: number): void {
  if (!shown.length) return;
  const at = shown.findIndex((v) => v.fingerprint === focused);
  const start = at < 0 ? (step >= 0 ? -1 : shown.length) : at;
  const next = shown[Math.max(0, Math.min(shown.length - 1, start + step))];
  if (!next) return;
  selected = new Set([next.fingerprint]);
  focused = anchor = next.fingerprint;
  renderList();
  document.getElementById(`key-${next.fingerprint}`)?.scrollIntoView({ block: 'nearest' });
}

export function importMenu(anchorNode: HTMLElement): void {
  menuAt(anchorNode, [
    { label: t('keys', 'From a file…'), action: () => ($('key-picker') as HTMLInputElement).click() },
    { label: t('keys', 'From the clipboard'), action: () => void importFromClipboard() },
    { label: t('keys', 'Paste as text…'), action: () => void importPasted() },
    { label: t('keys', 'Restore a key from its phrase…'), separated: true, action: () => void restoreFromPhrase() },
  ]);
}

export function focusSearch(): void {
  const search = $('search') as HTMLInputElement;
  search.focus();
  search.select();
}

export function bindKeyList(): void {
  selection.show = showKey;
  const list = $('key-rows');
  const search = $('search') as HTMLInputElement;
  const filter = $('filter') as HTMLSelectElement;
  filter.value = app.settings.filter;
  list.addEventListener('click', (event) => {
    const node = (event.target as Element).closest<HTMLElement>('.key-row');
    if (node?.dataset['fpr']) pick(node.dataset['fpr'], event);
    list.focus({ preventScroll: true });
  });
  list.addEventListener('contextmenu', (event) => {
    const node = (event.target as Element).closest<HTMLElement>('.key-row');
    const v = node?.dataset['fpr'] ? allViews().find((x) => x.fingerprint === node.dataset['fpr']) : undefined;
    if (!v) return;
    event.preventDefault();
    rowMenu(v, event.clientX, event.clientY);
  });
  list.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      move(event.key === 'ArrowDown' ? 1 : -1);
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      move(event.key === 'Home' ? -shown.length : shown.length);
    } else if ((event.key === 'Delete' || (event.key === 'Backspace' && (event.metaKey || event.ctrlKey))) && selected.size) {
      event.preventDefault();
      void deleteKeys(selectedViews());
    } else if (event.key === 'a' && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      selected = new Set(shown.map((v) => v.fingerprint));
      renderList();
    }
  });
  search.addEventListener('input', () => {
    query = search.value;
    renderList();
  });
  search.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      list.focus();
      move(0);
    } else if (event.key === 'Escape' && search.value) {
      event.stopPropagation();
      search.value = '';
      query = '';
      renderList();
    }
  });
  filter.addEventListener('change', () => {
    app.settings.filter = filter.value as KeyFilter;
    saveState();
    renderList();
  });
  for (const id of ['new-key', 'empty-new']) $(id).addEventListener('click', () => void newKeyPair());
  for (const id of ['import', 'empty-import']) $(id).addEventListener('click', (event) => importMenu(event.currentTarget as HTMLElement));
  $('empty-restore').addEventListener('click', () => void restoreFromPhrase());
  $('export').addEventListener('click', () => void exportPublic(selectedViews()));
  const picker = $('key-picker') as HTMLInputElement;
  picker.addEventListener('change', () => {
    const files = [...(picker.files ?? [])];
    picker.value = '';
    if (files.length) void importFiles(files);
  });
  onKeyringChange(() => {
    const present = new Set(allViews().map((v) => v.fingerprint));
    selected = new Set([...selected].filter((fp) => present.has(fp)));
    if (focused && !present.has(focused)) focused = null;
    renderList();
  });
  renderList();
}
