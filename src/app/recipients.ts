// Choosing whom to encrypt for: chosen keys as chips, and a field that finds keys by name,
// address or key ID as one types. A key not marked as verified is marked so. (After html-pgp.)

import { t } from '../core/i18n.ts';
import { allViews, keyIdLabel, label, ownSigning, validity } from './model.ts';
import type { KeyView } from './model.ts';
import { h, icon, ICONS } from './ui.ts';

export class RecipientPicker {
  readonly node: HTMLElement;
  private chosen: string[] = [];
  private readonly chips: HTMLElement;
  private readonly input: HTMLInputElement;
  private readonly list: HTMLElement;
  private suggestions: KeyView[] = [];
  private active = 0;
  private readonly onChange: () => void;

  constructor(onChange: () => void = () => undefined) {
    this.onChange = onChange;
    this.chips = h('span', { class: 'recipient-chips' });
    this.input = h('input', {
      class: 'recipient-input', type: 'text', autocomplete: 'off', spellcheck: 'false',
      placeholder: t('recipients', 'Name, email or key ID'), 'aria-label': t('recipients', 'Add a recipient'),
      role: 'combobox', 'aria-expanded': 'false', 'aria-autocomplete': 'list',
    });
    this.list = h('div', { class: 'recipient-list', role: 'listbox', hidden: '' });
    const box = h('div', { class: 'recipients' }, this.chips, this.input);
    box.addEventListener('mousedown', (event) => {
      if (event.target === box) {
        event.preventDefault();
        this.input.focus();
      }
    });
    this.node = h('div', { class: 'recipient-picker' }, box, this.list);
    this.input.addEventListener('input', () => this.suggest());
    this.input.addEventListener('focus', () => this.suggest());
    this.input.addEventListener('blur', () => window.setTimeout(() => this.close(), 120));
    this.input.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        if (this.list.hidden) this.suggest();
        const n = this.suggestions.length;
        if (n) this.active = (this.active + (event.key === 'ArrowDown' ? 1 : n - 1)) % n;
        this.paint();
      } else if (event.key === 'Enter') {
        const pick = this.suggestions[this.active];
        if (!this.list.hidden && pick) {
          event.preventDefault();
          this.add(pick.fingerprint);
        }
      } else if (event.key === 'Backspace' && !this.input.value && this.chosen.length) {
        this.remove(this.chosen[this.chosen.length - 1]);
      } else if (event.key === 'Escape' && !this.list.hidden) {
        event.stopPropagation();
        this.close();
      }
    });
    this.list.addEventListener('mousedown', (event) => {
      const option = (event.target as Element).closest<HTMLElement>('[data-fpr]');
      if (!option?.dataset['fpr']) return;
      event.preventDefault();
      this.add(option.dataset['fpr']);
    });
  }

  views(): KeyView[] {
    const all = allViews();
    return this.chosen.map((fp) => all.find((v) => v.fingerprint === fp)).filter((v): v is KeyView => !!v && v.canEncrypt);
  }

  set(fingerprints: string[]): void {
    const all = allViews();
    this.chosen = fingerprints.filter((fp) => all.find((v) => v.fingerprint === fp)?.canEncrypt);
    this.render();
  }

  refresh(): void {
    this.set(this.chosen);
  }

  pending(): string {
    return this.input.value.trim();
  }

  private add(fingerprint: string): void {
    if (!this.chosen.includes(fingerprint)) this.chosen.push(fingerprint);
    this.input.value = '';
    this.render();
    this.suggest();
    this.onChange();
  }

  private remove(fingerprint: string): void {
    this.chosen = this.chosen.filter((fp) => fp !== fingerprint);
    this.render();
    this.onChange();
  }

  private render(): void {
    this.chips.replaceChildren(
      ...this.views().map((v) => {
        const valid = validity(v);
        const remove = h('button', { type: 'button', class: 'chip-remove', title: t('recipients', 'Remove'), 'aria-label': t('recipients', 'Remove') }, icon(ICONS.close));
        remove.addEventListener('click', () => this.remove(v.fingerprint));
        return h(
          'span',
          { class: `recipient recipient--${valid.tone}`, title: `${label(v)} · ${keyIdLabel(v.keyId)} · ${valid.label}`, 'data-fpr': v.fingerprint },
          valid.tone === 'warn' ? icon(ICONS.warning) : null,
          h('span', { class: 'recipient-name', text: v.name || v.email || keyIdLabel(v.keyId) }),
          remove,
        );
      }),
    );
  }

  private suggest(): void {
    const words = this.input.value.toLowerCase().split(/\s+/).filter(Boolean);
    this.suggestions = allViews()
      .filter((v) => v.canEncrypt && !this.chosen.includes(v.fingerprint))
      .filter((v) => {
        const text = `${v.state.userIds.map((u) => u.text).join(' ')} ${v.fingerprint}`.toLowerCase();
        return words.every((word) => text.includes(word.replace(/^0x/, '')));
      })
      .slice(0, 8);
    this.active = 0;
    this.paint();
  }

  private paint(): void {
    const open = document.activeElement === this.input && this.suggestions.length > 0;
    this.list.hidden = !open;
    this.input.setAttribute('aria-expanded', String(open));
    this.list.replaceChildren(
      ...this.suggestions.map((v, i) => {
        const valid = validity(v);
        return h(
          'div',
          { class: `recipient-option${i === this.active ? ' recipient-option--active' : ''}`, role: 'option', 'data-fpr': v.fingerprint },
          h('span', { class: 'recipient-option-name', text: label(v) }),
          h('span', { class: `chip chip--${valid.tone}`, text: valid.label }),
          h('span', { class: 'mono recipient-option-id', text: v.keyId.slice(-8) }),
        );
      }),
    );
  }

  private close(): void {
    this.list.hidden = true;
    this.input.setAttribute('aria-expanded', 'false');
  }
}

/** Our keys that can sign, for a "Sign as" list; '' — do not sign. */
export function signerChoices(): { value: string; label: string }[] {
  return [...ownSigning().map((v) => ({ value: v.fingerprint, label: label(v) })), { value: '', label: t('recipients', 'Do not sign') }];
}

export const defaultSigner = (): string => ownSigning()[0]?.fingerprint ?? '';

