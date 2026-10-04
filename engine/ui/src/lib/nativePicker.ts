/**
 * The desktop window's native file and folder chooser.
 *
 * A browser file input never reveals where a file lives, so the desktop shell
 * (api/native_picker.py) serves the OS dialog over `/native-picker`. It returns
 * the absolute paths the operator chose and does nothing else; the caller puts
 * them in a text field, where they meet the same validation as typed ones.
 * Outside the desktop window - the dev server, a plain browser - the API says
 * it is unavailable and the caller falls back to typing.
 *
 * This is a plain same-origin request on purpose: pywebview's own JS bridge is
 * built with `new Function`, which the page's Content-Security-Policy forbids.
 */

export type PickKind = 'file' | 'files' | 'folder'

/** The one thing of `fetch` used; a parameter so it can be faked. */
export type PickerFetch = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; json: () => Promise<unknown> }>

const ENDPOINT = '/native-picker'

/** Whether this launch has a native window to open a dialog on. */
export async function pickerAvailable(
  fetcher: PickerFetch = globalThis.fetch as PickerFetch,
): Promise<boolean> {
  try {
    const response = await fetcher(ENDPOINT)
    if (!response.ok) return false
    const body = (await response.json()) as { available?: unknown }
    return body.available === true
  } catch {
    return false
  }
}

/** The chosen paths; empty when cancelled, unavailable, or the dialog failed. */
export async function pickPaths(
  kind: PickKind,
  fetcher: PickerFetch = globalThis.fetch as PickerFetch,
): Promise<string[]> {
  try {
    const response = await fetcher(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind }),
    })
    if (!response.ok) return []
    const body = (await response.json()) as { paths?: unknown }
    if (!Array.isArray(body.paths)) return []
    return body.paths.filter((item): item is string => typeof item === 'string' && item !== '')
  } catch {
    return []
  }
}
