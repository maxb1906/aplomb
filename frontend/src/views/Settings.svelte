<script lang="ts">
  import { onMount } from 'svelte'
  import { api, errText } from '../lib/api'
  import { t } from '../lib/i18n.svelte'
  import { app, toast } from '../lib/state.svelte'
  import type { Config } from '../lib/types'
  import Icon from '../lib/Icon.svelte'

  const allFormats = ['html', 'md', 'json', 'ps1']
  let cfg = $state<Config | null>(null)
  let saving = $state(false)

  onMount(async () => {
    try { cfg = await (await api()).GetConfig() } catch (e) { toast(errText(e), 'error') }
  })

  function toggle(f: string, on: boolean) {
    if (!cfg) return
    cfg.formats = allFormats.filter((x) => (x === f ? on : cfg!.formats.includes(x)))
  }
  async function chooseLogo() {
    try {
      const p = await (await api()).ChooseLogo()
      if (p && cfg) cfg.logo = p
    } catch (e) { toast(errText(e), 'error') }
  }
  async function save() {
    if (!cfg) return
    saving = true
    try {
      const b = await api()
      await b.SaveConfig($state.snapshot(cfg))
      cfg = await b.GetConfig()
      if (app.init) app.init.config = $state.snapshot(cfg)
      toast(t('gui.settings.saved'))
    } catch (e) { toast(errText(e), 'error') } finally { saving = false }
  }
</script>

<div class="page">
  <header>
    <h1>{t('gui.settings.title')}</h1>
    <p class="muted">{t('gui.settings.lead')} <span class="mono small selectable">{app.init?.data_dir}</span></p>
  </header>

  {#if cfg}
    <section class="card grid">
      <h2 class="full">{t('gui.settings.cover')}</h2>
      <label class="field"><span>{t('gui.field.technician')}</span><input type="text" bind:value={cfg.technician} /></label>
      <label class="field"><span>{t('gui.field.company')}</span><input type="text" bind:value={cfg.company} /></label>
      <div class="field full"><span class="lbl">{t('gui.field.logo')}</span>
        <div class="row">
          <input type="text" bind:value={cfg.logo} placeholder="logo.png" />
          <button class="btn" onclick={chooseLogo}><Icon name="image" /> {t('gui.settings.logo_choose')}</button>
          {#if cfg.logo}<button class="btn ghost" title={t('gui.settings.logo_clear')} onclick={() => (cfg!.logo = '')}><Icon name="x" /></button>{/if}
        </div>
        <p class="small muted hint">{t('gui.settings.logo_hint')}</p>
      </div>
    </section>

    <section class="card grid">
      <h2 class="full">{t('gui.settings.audit')}</h2>
      <label class="field"><span>{t('gui.field.ui_lang')}</span>
        <select bind:value={cfg.lang}>
          <option value="">{t('gui.lang.auto')}</option>
          {#each app.init?.languages ?? [] as l}<option value={l}>{t('gui.lang.' + l)}</option>{/each}
        </select>
      </label>
      <label class="field"><span>{t('gui.field.report_lang')}</span>
        <select bind:value={cfg.report_lang}>
          <option value="">{t('gui.lang.same')}</option>
          {#each app.init?.languages ?? [] as l}<option value={l}>{t('gui.lang.' + l)}</option>{/each}
        </select>
      </label>
      <label class="field"><span>{t('gui.field.profile')}</span>
        <select bind:value={cfg.profile}>
          <option value="">{t('gui.profile.auto')}</option>
          <option value="workstation">{t('role.workstation')}</option>
          <option value="server">{t('role.server')}</option>
          <option value="dc">{t('role.dc')}</option>
        </select>
      </label>
      <div class="field"><span class="lbl">{t('gui.field.formats')}</span>
        <div class="row wrap">
          {#each allFormats as f}
            <label class="check"><input type="checkbox" checked={cfg.formats.includes(f)} onchange={(e) => toggle(f, e.currentTarget.checked)} /> {t('gui.format.' + f)}</label>
          {/each}
        </div>
      </div>
    </section>

    <section class="card">
      <h2>{t('gui.settings.accepted')}</h2>
      <p class="small muted">{t('gui.settings.accepted_lead')}</p>
      {#if !cfg.disabled?.length}
        <p class="muted">{t('gui.results.no_accepted')}</p>
      {:else}
        <div class="acc">
          {#each cfg.disabled as d, i}
            <div class="row accrow">
              <div class="who"><span class="mono small">{d.id}</span><div class="small">{d.title ?? ''}</div></div>
              <input type="text" class="grow" bind:value={d.reason} placeholder={t('gui.accept.reason')} />
              <button class="btn ghost danger" title={t('gui.item.revoke')} onclick={() => cfg!.disabled!.splice(i, 1)}><Icon name="x" /></button>
            </div>
          {/each}
        </div>
      {/if}
    </section>

    <div class="row"><span class="grow"></span>
      <button class="btn primary" disabled={saving} onclick={save}><Icon name="check" /> {t('gui.settings.save')}</button>
    </div>
  {/if}
</div>

<style>
  .page { max-width: 860px; display: grid; gap: 16px }
  header p { margin: 4px 0 0 }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px }
  .full { grid-column: 1 / -1 } h2.full { margin: 0 }
  .lbl { display: block; font-size: 12.5px; color: var(--muted); margin-bottom: 4px; font-weight: 500 }
  .hint { margin: 6px 0 0 }
  .acc { display: grid; gap: 8px; margin-top: 8px }
  .accrow { gap: 12px } .who { width: 260px; flex: none }
</style>
