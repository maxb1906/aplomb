// Déroulement d'un audit : il continue même si l'on change d'écran.
import { api, errText, onEvent } from './api'
import { app, toast } from './state.svelte'
import type { Progress, Result } from './types'

export const run = $state<{ current: number; total: number; done: string[]; error: string; started: number }>({
  current: -1, total: 0, done: [], error: '', started: 0,
})

let wired = false
function wire() {
  if (wired) return
  wired = true
  onEvent('audit:progress', (p: Progress) => {
    if (run.current >= 0 && app.init) run.done.push(app.init.sections[run.current])
    run.current = p.index
    run.total = p.total
  })
  onEvent('audit:done', (r: Result) => {
    app.auditing = false
    app.result = r
    app.page = 'results'
    run.current = -1
  })
  onEvent('audit:error', (msg: string) => {
    app.auditing = false
    run.error = msg
    run.current = -1
    toast(msg, 'error')
  })
}

export async function startAudit(profile: string, reportLang: string) {
  wire()
  run.current = -1
  run.done = []
  run.error = ''
  run.total = app.init?.sections.length ?? 0
  run.started = Date.now()
  try {
    app.auditing = true
    await (await api()).StartAudit({ profile, report_lang: reportLang })
  } catch (e) {
    app.auditing = false
    run.error = errText(e)
    toast(run.error, 'error')
  }
}
