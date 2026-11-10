// Handing data out: a file to save, or text on the clipboard. (From html-pgp.)

import { t } from '../core/i18n.ts';
import { isTouch } from './screens.ts';

export function download(data: string | Uint8Array, name: string, type = 'application/octet-stream'): void {
  const blob = new Blob([data as BlobPart], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 30000);
}

const shareable = (data: string | Uint8Array, name: string): File => new File([data as BlobPart], name, { type: 'application/octet-stream' });

/**
 * On a phone that can take a file through the share sheet — iOS, where
 * "Save to Files" lives — the file goes there; everywhere else it downloads.
 */
function sharesFiles(): boolean {
  try {
    return isTouch() && typeof navigator.share === 'function' && typeof navigator.canShare === 'function' && navigator.canShare({ files: [shareable('', 'key.asc')] });
  } catch {
    return false;
  }
}

export async function saveFile(data: string | Uint8Array, name: string): Promise<void> {
  if (sharesFiles()) {
    try {
      await navigator.share({ files: [shareable(data, name)], title: name });
      return;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return;
      // NotAllowedError: the tap that asked is too long ago, after a slow operation.
    }
  }
  download(data, name, typeof data === 'string' ? 'text/plain' : 'application/octet-stream');
}

export async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      /* not focused or not allowed — try the older route */
    }
  }
  const area = document.createElement('textarea');
  area.value = value;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  if (!ok) throw new Error(t('errors', 'The browser refused to copy'));
}

export async function readClipboard(): Promise<string> {
  if (!navigator.clipboard?.readText) throw new Error(t('errors', 'This browser does not let the page read the clipboard: paste the text instead'));
  return navigator.clipboard.readText();
}

/** A file name from a person's name: letters and digits kept, in any script, the rest an underscore. */
export function safeName(text: string): string {
  return text.normalize('NFC').replace(/[^\p{L}\p{N}@.+-]+/gu, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'key';
}
