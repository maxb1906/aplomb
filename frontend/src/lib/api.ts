// Accès au backend Go (méthodes liées par Wails sur window.go.gui.App).
// Hors Wails (npm run dev), un jeu de démonstration tiré des fixtures est chargé.
import type { Config, Entry, Init, Result } from './types'

export type Backend = {
  Init(): Promise<Init>
  Strings(lang: string): Promise<Record<string, string>>
  GetConfig(): Promise<Config>
  SaveConfig(c: Config): Promise<void>
  ChooseLogo(): Promise<string>
  StartAudit(o: { profile: string; report_lang: string }): Promise<void>
  Current(): Promise<Result | null>
  History(): Promise<Entry[]>
  OpenReport(path: string): Promise<Result>
  AcceptRisk(id: string, reason: string): Promise<Result | null>
  RevokeRisk(id: string): Promise<Result | null>
  OpenPath(path: string): Promise<void>
  OpenDataDir(): Promise<void>
  RelaunchAdmin(): Promise<void>
}

const w = window as any
export const isWails = typeof w.go?.gui?.App !== 'undefined'

let backend: Backend | null = null

export async function api(): Promise<Backend> {
  if (backend) return backend
  if (isWails) backend = w.go.gui.App as Backend
  else if (import.meta.env.DEV) backend = (await import('./mock/mock')).mock
  else throw new Error('backend unavailable')
  return backend!
}

export function onEvent(name: string, cb: (data: any) => void): () => void {
  if (w.runtime?.EventsOn) return w.runtime.EventsOn(name, cb)
  return mockBus.on(name, cb)
}

export function emit(name: string, data?: unknown) {
  if (w.runtime?.EventsEmit) w.runtime.EventsEmit(name, data)
}

// Liens externes : jamais dans la fenêtre, toujours dans le navigateur.
export function openURL(url: string) {
  if (w.runtime?.BrowserOpenURL) w.runtime.BrowserOpenURL(url)
  else window.open(url, '_blank', 'noopener')
}

export async function copyText(text: string): Promise<boolean> {
  try {
    if (w.runtime?.ClipboardSetText) return await w.runtime.ClipboardSetText(text)
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

// Bus d'évènements du mode démonstration.
export const mockBus = (() => {
  const subs: Record<string, ((d: any) => void)[]> = {}
  return {
    on(name: string, cb: (d: any) => void) {
      ;(subs[name] ||= []).push(cb)
      return () => { subs[name] = subs[name].filter((f) => f !== cb) }
    },
    emit(name: string, d: any) { (subs[name] || []).forEach((f) => f(d)) },
  }
})()

// Message d'une erreur renvoyée par Go (chaîne) ou JS.
export function errText(e: unknown): string {
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return String(e)
}
