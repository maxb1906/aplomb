// Backend de démonstration (npm run dev) : données générées par
// « go run ./tools/guimock » à partir des fixtures de testdata/.
import type { Backend } from '../api'
import { mockBus } from '../api'
import type { Config, Entry, Init, Result } from '../types'
import data from './data.json'

const d = data as unknown as Record<string, any>
let lang = 'fr'
let current: Result | null = null
let config: Config = structuredClone(d.config_fr)
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))

export const mock: Backend = {
  async Init() {
    const init = structuredClone(d['init_' + lang]) as Init
    init.has_current = current !== null
    return init
  },
  async Strings(l) { lang = l; return d['init_' + l].strings },
  async GetConfig() { return structuredClone(config) },
  async SaveConfig(c) { config = structuredClone(c) },
  async ChooseLogo() { return 'logo.png' },
  async StartAudit() {
    const sections: string[] = d.init_fr.sections
    ;(async () => {
      for (let i = 0; i < sections.length; i++) {
        mockBus.emit('audit:progress', { section: sections[i], label: sections[i], index: i, total: sections.length })
        await wait(350)
      }
      current = structuredClone(d['result_' + lang])
      mockBus.emit('audit:done', current)
    })()
  },
  async Current() { return current ? structuredClone(d['result_' + lang]) : null },
  async History() { return d.history as Entry[] },
  async OpenReport() { current = structuredClone(d['result_' + lang]); return current! },
  async AcceptRisk() { return current },
  async RevokeRisk() { return current },
  async OpenPath() {},
  async OpenDataDir() {},
  async RelaunchAdmin() {},
}
