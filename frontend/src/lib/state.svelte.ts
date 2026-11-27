import type { Init, Result } from './types'

export type Page = 'audit' | 'results' | 'history' | 'settings'

export const app = $state<{ page: Page; init: Init | null; result: Result | null; auditing: boolean }>({
  page: 'audit', init: null, result: null, auditing: false,
})

type Toast = { id: number; kind: 'ok' | 'error'; text: string }
export const toasts = $state<{ list: Toast[] }>({ list: [] })
let seq = 0

export function toast(text: string, kind: 'ok' | 'error' = 'ok') {
  const id = ++seq
  toasts.list.push({ id, kind, text })
  setTimeout(() => { toasts.list = toasts.list.filter((x) => x.id !== id) }, kind === 'error' ? 7000 : 2600)
}
