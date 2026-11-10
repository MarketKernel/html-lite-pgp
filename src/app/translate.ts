// The page's own markup in the chosen language (after html-pgp's i18n.ts).
//
// data-i18n="context" translates an element's text. A child marked data-slot="name" stays as
// it is and stands in the text as {name}. data-i18n-attr="context" translates the element's
// title, placeholder and aria-label.

import { t } from '../core/i18n.ts';

const ATTRIBUTES = ['title', 'placeholder', 'aria-label'] as const;

interface Source {
  text: string;
  slots: Map<string, Element>;
}

const contents = new WeakMap<Element, Source>();
const attributes = new WeakMap<Element, Partial<Record<(typeof ATTRIBUTES)[number], string>>>();

function sourceOf(element: Element): Source {
  let source = contents.get(element);
  if (!source) {
    const slots = new Map<string, Element>();
    let text = '';
    for (const node of Array.from(element.childNodes)) {
      const slot = node instanceof Element ? node.getAttribute('data-slot') : null;
      if (slot && node instanceof Element) {
        slots.set(slot, node);
        text += `{${slot}}`;
      } else text += node.textContent ?? '';
    }
    source = { text: text.replace(/\s+/g, ' ').trim(), slots };
    contents.set(element, source);
  }
  return source;
}

export function translatePage(root: ParentNode = document): void {
  for (const element of Array.from(root.querySelectorAll('[data-i18n]'))) {
    const context = element.getAttribute('data-i18n') ?? '';
    const { text, slots } = sourceOf(element);
    const parts = t(context, text).split(/(\{\w+\})/);
    element.replaceChildren(...parts.filter(Boolean).map((part) => slots.get(part.slice(1, -1)) ?? document.createTextNode(part)));
  }
  for (const element of Array.from(root.querySelectorAll('[data-i18n-attr]'))) {
    const context = element.getAttribute('data-i18n-attr') ?? '';
    let source = attributes.get(element);
    if (!source) {
      source = {};
      for (const name of ATTRIBUTES) {
        const value = element.getAttribute(name);
        if (value) source[name] = value;
      }
      attributes.set(element, source);
    }
    for (const [name, value] of Object.entries(source)) element.setAttribute(name, t(context, value));
  }
}
