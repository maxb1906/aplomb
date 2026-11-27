<script lang="ts">
  import { api, errText } from '../lib/api'
  import { t, fmtDate } from '../lib/i18n.svelte'
  import { app, toast } from '../lib/state.svelte'
  import { run, startAudit } from '../lib/audit.svelte'
  import Icon from '../lib/Icon.svelte'

  const init = app.init!
  let profile = $state(init.config.profile || '')
  let reportLang = $state(init.config.report_lang || '')

  async function elevate() {
    try { await (await api()).RelaunchAdmin() } catch (e) { toast(errText(e), 'error') }
  }
  let pct = $derived(run.total ? Math.round((100 * (run.done.length)) / run.total) : 0)
</script>

<div class="page">
  <header>
    <h1>{t('gui.audit.title')}</h1>
    <p class="muted">{t('gui.audit.lead')}</p>
  </header>

  {#if !init.can_audit}
    <div class="note warn">{t('audit.not_windows')}</div>
  {/if}

  <section class="card machine">
    <div class="row wrap">
      <div class="grow">
        <div class="muted small">{t('gui.audit.machine')}</div>
        <div class="host selectable">{init.hostname}</div>
      </div>
      {#if init.elevated}
        <span class="chip ok"><Icon name="admin" /> {t('gui.audit.elevated')}</span>
      {:else}
        <span class="chip warn"><Icon name="shield" /> {t('gui.audit.not_elevated')}</span>
      {/if}
    </div>
    {#if !init.elevated}
      <div class="elev">
        <div class="grow">
          <strong>{t('gui.audit.elevate_title')}</strong>
          <p class="small muted">{t('gui.audit.elevate_text')}</p>
        </div>
        <button class="btn" onclick={elevate} disabled={app.auditing}><Icon name="admin" /> {t('gui.audit.elevate')}</button>
      </div>
    {/if}
  </section>

  <section class="card">
    <div class="opts">
      <label class="field"><span>{t('gui.field.profile')}</span>
        <select bind:value={profile} disabled={app.auditing}>
          <option value="">{t('gui.profile.auto')}</option>
          <option value="workstation">{t('role.workstation')}</option>
          <option value="server">{t('role.server')}</option>
          <option value="dc">{t('role.dc')}</option>
        </select>
      </label>
      <label class="field"><span>{t('gui.field.report_lang')}</span>
        <select bind:value={reportLang} disabled={app.auditing}>
          <option value="">{t('gui.lang.same')}</option>
          {#each init.languages as l}<option value={l}>{t('gui.lang.' + l)}</option>{/each}
        </select>
      </label>
    </div>
    <div class="row launch">
      <button class="btn primary big" disabled={app.auditing || !init.can_audit} onclick={() => startAudit(profile, reportLang)}>
        {#if app.auditing}<span class="spin light"></span> {t('gui.audit.running')}{:else}<Icon name="play" /> {t('gui.audit.start')}{/if}
      </button>
      <p class="small muted grow"><Icon name="lock" size={13} /> {t('gui.audit.readonly')}</p>
    </div>
  </section>

  {#if app.auditing || run.done.length}
    <section class="card">
      <div class="row between"><h2>{t('gui.audit.progress')}</h2><span class="muted small">{pct} %</span></div>
      <div class="bar"><div style="width:{app.auditing ? Math.max(pct, 3) : 100}%"></div></div>
      <ul class="steps">
        {#each init.sections as s, i}
          {@const done = run.done.includes(s) || (!app.auditing && run.done.length > 0)}
          <li class:done class:cur={i === run.current}>
            {#if done}<Icon name="check" />{:else if i === run.current}<span class="spin"></span>{:else}<span class="dot"></span>{/if}
            {t('section.' + s)}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if app.result && !app.auditing}
    <button class="card last" onclick={() => (app.page = 'results')}>
      <span class="grade grade-{app.result.score.grade}">{app.result.score.grade}</span>
      <span class="grow">
        <strong>{t('gui.audit.last')}</strong>
        <span class="muted small">{fmtDate(app.result.meta.collected_at)} · {app.result.score.score >= 0 ? app.result.score.score + '/100' : '—'}</span>
      </span>
      <Icon name="chevron" />
    </button>
  {/if}
</div>

<style>
  .page { max-width: 860px; display: grid; gap: 16px }
  header p { margin-top: 4px; max-width: 640px }
  .host { font-size: 20px; font-weight: 700; word-break: break-all }
  .chip { display: inline-flex; align-items: center; gap: 6px; border-radius: 999px; padding: 4px 12px; font-weight: 600; font-size: 13px }
  .chip.ok { background: var(--ok-bg); color: var(--ok) } .chip.warn { background: var(--warn-bg); color: var(--warn) }
  .elev { display: flex; gap: 14px; align-items: center; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--line) }
  .elev p { margin: 2px 0 0 }
  .opts { display: grid; grid-template-columns: 1fr 1fr; gap: 14px }
  .launch { margin-top: 16px; gap: 16px }
  .launch p { margin: 0 } .launch p :global(svg) { vertical-align: -2px }
  .spin.light { border-color: rgba(255,255,255,.35); border-top-color: #fff }
  .bar { height: 6px; background: var(--line); border-radius: 6px; overflow: hidden; margin: 6px 0 12px }
  .bar div { height: 100%; background: var(--accent); transition: width .3s }
  .steps { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 6px 18px }
  .steps li { display: flex; align-items: center; gap: 8px; color: var(--faint) }
  .steps li.done { color: var(--ok) } .steps li.cur { color: var(--ink); font-weight: 600 }
  .dot { width: 16px; height: 16px; display: inline-grid; place-items: center } .dot::after { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--line) }
  .last { display: flex; align-items: center; gap: 14px; text-align: left; cursor: pointer; width: 100% }
  .last:hover { background: var(--hover) }
  .last span.grow { display: grid }
  .grade { font-size: 28px; font-weight: 800; width: 40px; text-align: center }
</style>
