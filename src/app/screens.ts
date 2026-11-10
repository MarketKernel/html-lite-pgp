/**
 * Phones: one screen at a time.
 *
 * Up to 900px wide — a phone, or a tablet held upright — the key list and a
 * key's details take the window in turn, and menus rise from the bottom as
 * sheets. Each of these layers, and each dialog, puts a step into the
 * browser's history, so the system's back button — or a swipe — closes the
 * one on top, as it does in any app. On a wider window nothing here does
 * anything: no class is set and no history is written.
 *
 * Nothing runs on import: the Node tests load modules that import this one.
 */

export type Layer = 'details' | 'sheet' | 'dialog';

const NARROW = '(max-width: 900px)';

const matches = (query: string): boolean => typeof matchMedia === 'function' && matchMedia(query).matches;

/** The phone layout is on. */
export const isNarrow = (): boolean => matches(NARROW);

/** No mouse to point with: a phone or a tablet, whatever its width. */
export const isTouch = (): boolean => matches('(hover: none)');

/** The layers this page has put into the history, bottom first; a step's state holds its depth. */
const stack: Layer[] = [];
/** Steps back the page took itself: their popstate changes nothing. */
let silent = 0;
let syncTimer = 0;

const classes = (): DOMTokenList => document.body.classList;

function count(layer: Layer): number {
  switch (layer) {
    case 'details':
      return classes().contains('show-details') ? 1 : 0;
    case 'sheet':
      return document.querySelectorAll('.context-menu--sheet').length;
    case 'dialog':
      return document.querySelectorAll('.overlay').length;
  }
}

function depthOf(state: unknown): number {
  const value = (state as { pgp?: unknown } | null)?.pgp;
  return typeof value === 'number' ? value : 0;
}

/** Records a layer that has just opened. */
export function opened(layer: Layer): void {
  if (!isNarrow() || silent > 0) return;
  try {
    stack.push(layer);
    history.pushState({ pgp: stack.length }, '');
  } catch {
    // No history to write to: the buttons still open and close everything.
    stack.length = 0;
  }
}

/** Something closed: the history steps back over the closed layers on top, soon. */
export function closed(): void {
  window.clearTimeout(syncTimer);
  // Later, not now: a menu item that opens a dialog closes the menu first.
  syncTimer = window.setTimeout(sync, 0);
}

/** How many of the recorded layers of each kind are still open, from the top of the stack down. */
function closedOnTop(): number {
  const open = { details: count('details'), sheet: count('sheet'), dialog: count('dialog') };
  const seen = { details: 0, sheet: 0, dialog: 0 };
  // Walking from the bottom: a layer is open while there are still that many of its kind.
  let lastOpen = -1;
  stack.forEach((layer, index) => {
    seen[layer] += 1;
    if (seen[layer] <= open[layer]) lastOpen = index;
  });
  return stack.length - 1 - lastOpen;
}

function sync(): void {
  if (silent > 0) return;
  const steps = closedOnTop();
  if (steps <= 0) return;
  stack.length -= steps;
  silent += 1;
  history.go(-steps);
}

function onPopState(event: PopStateEvent): void {
  if (silent > 0) {
    silent -= 1;
    if (silent === 0) closed();
    return;
  }
  const depth = depthOf(event.state);
  if (depth > stack.length) {
    silent += 1;
    history.go(stack.length - depth);
    return;
  }
  // The user went back: whatever was above that step closes, the top first.
  for (const layer of stack.splice(depth).reverse()) close(layer);
  closed();
}

function close(layer: Layer): void {
  switch (layer) {
    case 'sheet':
      document.querySelector('.context-menu--sheet')?.dispatchEvent(new Event('dismiss'));
      return;
    case 'dialog': {
      const overlays = document.querySelectorAll('.overlay');
      overlays[overlays.length - 1]?.dispatchEvent(new Event('dismiss'));
      return;
    }
    case 'details':
      classes().remove('show-details');
      return;
  }
}

/** Shows a key's details on their own screen, over the list. */
export function showDetails(): void {
  if (!isNarrow() || classes().contains('show-details')) return;
  classes().add('show-details');
  opened('details');
}

/** Back to the list. */
export function hideDetails(): void {
  if (!classes().contains('show-details')) return;
  classes().remove('show-details');
  closed();
}

/** The back button in the toolbar: the same as the system's. */
export function back(): void {
  if (stack.at(-1) === 'details' && silent === 0) history.back();
  else hideDetails();
}

export function bindScreens(hasDetails: () => boolean): void {
  // Steps a previous load of the page left in the history lead nowhere now.
  if (depthOf(history.state) > 0) history.replaceState(null, '');
  window.addEventListener('popstate', onPopState);
  if (typeof matchMedia !== 'function') return;
  matchMedia(NARROW).addEventListener('change', () => {
    if (isNarrow()) {
      if (hasDetails() && classes().contains('details-open')) showDetails();
      return;
    }
    classes().remove('show-details');
    for (const node of document.querySelectorAll('.context-menu--sheet')) node.dispatchEvent(new Event('dismiss'));
    closed();
  });
}
