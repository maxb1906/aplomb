<script lang="ts">
  import { api, errText } from '../lib/api'
  import { t, fmtDate } from '../lib/i18n.svelte'
  import { app, toast } from '../lib/state.svelte'
  import type { Item } from '../lib/types'
  import Gauge from '../lib/Gauge.svelte'
  import Icon from '../lib/Icon.svelte'
  import IssueCard from '../lib/IssueCard.svelte'
  import Modal from '../lib/Modal.svelte'

  let r = $derived(app.result!)
  let v = $derived(r.view)
  let c = $derived(r.score.counts)
  let issues = $derived(v.issues ?? [])
  let notChecked = $derived(v.not_checked ?? [])
  let accepted = $derived(v.accepted ?? [])

  type Tab = 'issues' | 'categories' | 'not_checked' | 'accepted' | 'host'
  let tab = $state<Tab>('issues')
  let levels = $state<Record<string, boolean>>({ critical: true, warning: true, info: true })
  let category = $state('')
  let query = $state('')
  let expandAll = $state(false)

  let filtered = $derived(issues.filter((it) =>
    levels[it.level] && (!category || it.category === category) &&
    (!query || (it.title + ' ' + it.id + ' ' + (it.summary ?? '') + ' ' + (it.findings ?? []).map((f) => f.object).join(' '))
      .toLowerCase().includes(query.toLowerCase()))))

  async function open(kind: string) {
    const p = kind === 'dir' ? r.dir : r.files[kind]
    if (!p) return
    try { await (await api()).OpenPath(p) } catch (e) { toast(errText(e), 'error') }
  }

  // Risque accepté : justification obligatoire, enregistrée dans config.yaml.
  let accepting = $state<Item | null>(null)
  let reason = $state('')
  let busy = $state(false)
  async function confirmAccept() {
    if (!accepting) return
    busy = true
    try {
      const res = await (await api()).AcceptRisk(accepting.id, reason)
      if (res) app.result = res
      toast(t('gui.accept.done', { id: accepting.id }))
      accepting = null
      reason = ''
    } catch (e) { toast(errText(e), 'error') } finally { busy = false }
  }
  async function revoke(it: Item) {
    try {
      const res = await (await api()).RevokeRisk(it.id)
      if (res) app.result = res
      toast(t('gui.accept.revoked', { id: it.id }))
    } catch (e) { toast(errText(e), 'error') }
  }
  function showCategory(id: string) { category = id; tab = 'issues' }
</script>

<div class="page">
  {#if r.source === 'history'}
    <div class="note info row"><Icon name="history" /> {t('gui.results.from_history', { date: fmtDate(r.meta.collected_at) })}</div>
  {/if}

  <section class="card top">
    <div class="gauge">
      <Gauge score={r.score.score} grade={r.score.grade} />
      <div class="grade grade-{r.score.grade}">{t('gui.results.grade', { grade: r.score.grade })}</div>
    </div>
    <div class="grow">
      <div class="row wrap between">
        <div>
          <h1 class="selectable">{v.host_rows[0]?.v}</h1>
          <div class="muted small">{fmtDate(r.meta.collected_at)} · {t('role.' + r.meta.profile)}{r.meta.technician ? ' · ' + r.meta.technician : ''}{r.meta.company ? ' · ' + r.meta.company : ''}</div>
        </div>
        {#if v.logo}<img class="logo" src={v.logo} alt="" />{/if}
      </div>
      <ul class="summary">{#each v.summary as s}<li>{s}</li>{/each}</ul>
      <div class="counts">
        <button class="cnt critical" onclick={() => { levels = { critical: true, warning: false, info: false }; tab = 'issues' }}><b>{c.critical}</b> {t('level.critical')}</button>
        <button class="cnt warning" onclick={() => { levels = { critical: false, warning: true, info: false }; tab = 'issues' }}><b>{c.warning}</b> {t('level.warning')}</button>
        <button class="cnt info" onclick={() => { levels = { critical: false, warning: false, info: true }; tab = 'issues' }}><b>{c.info}</b> {t('level.info')}</button>
        <button class="cnt pass" onclick={() => (tab = 'categories')}><b>{c.pass}</b> {t('status.pass')}</button>
        <button class="cnt na" onclick={() => (tab = 'not_checked')}><b>{c.not_checked}</b> {t('status.not_checked')}</button>
      </div>
      <div class="cov">
        <div class="row between small"><span class="muted">{t('gui.results.coverage')}</span><b>{r.score.coverage} %</b></div>
        <div class="bar"><div style="width:{r.score.coverage}%"></div></div>
      </div>
    </div>
  </section>

  <div class="row wrap actions">
    {#if r.files.html}<button class="btn" onclick={() => open('html')}><Icon name="external" /> {t('gui.results.open_html')}</button>{/if}
    {#if r.files.ps1}<button class="btn" onclick={() => open('ps1')}><Icon name="script" /> {t('gui.results.open_ps1')}</button>{/if}
    {#if r.files.md}<button class="btn" onclick={() => open('md')}><Icon name="file" /> {t('gui.results.open_md')}</button>{/if}
    <button class="btn" onclick={() => open('dir')}><Icon name="folder" /> {t('gui.results.open_dir')}</button>
    <span class="grow"></span>
    <span class="muted small conf"><Icon name="lock" size={13} /> {t('gui.results.confidential')}</span>
  </div>

  <div class="tabs">
    <button class:on={tab === 'issues'} onclick={() => (tab = 'issues')}>{t('gui.tab.issues')}<span class="n">{issues.length}</span></button>
    <button class:on={tab === 'categories'} onclick={() => (tab = 'categories')}>{t('gui.tab.categories')}</button>
    <button class:on={tab === 'not_checked'} onclick={() => (tab = 'not_checked')}>{t('gui.tab.not_checked')}<span class="n">{notChecked.length}</span></button>
    <button class:on={tab === 'accepted'} onclick={() => (tab = 'accepted')}>{t('gui.tab.accepted')}<span class="n">{accepted.length}</span></button>
    <button class:on={tab === 'host'} onclick={() => (tab = 'host')}>{t('gui.tab.host')}</button>
  </div>

  {#if tab === 'issues'}
    <div class="row wrap filters">
      {#each ['critical', 'warning', 'info'] as l}
        <label class="check chip-{l}" class:off={!levels[l]}><input type="checkbox" bind:checked={levels[l]} /> {t('level.' + l)}</label>
      {/each}
      <select bind:value={category} class="cat">
        <option value="">{t('gui.filter.all_categories')}</option>
        {#each v.categories as cv}<option value={cv.id}>{cv.label}</option>{/each}
      </select>
      <div class="search grow"><Icon name="search" /><input type="search" placeholder={t('gui.filter.search')} bind:value={query} /></div>
      <button class="btn ghost" onclick={() => (expandAll = !expandAll)}>{expandAll ? t('gui.filter.collapse') : t('gui.filter.expand')}</button>
    </div>
    {#if issues.length === 0}
      <div class="empty card"><Icon name="check" size={28} /><p>{t('summary.no_issue')}</p></div>
    {:else if filtered.length === 0}
      <div class="empty">{t('gui.filter.none')}</div>
    {:else}
      <div class="list">
        {#each filtered as it (it.id)}<IssueCard item={it} open={expandAll} onaccept={(x) => { accepting = x; reason = '' }} />{/each}
      </div>
    {/if}
  {:else if tab === 'categories'}
    <div class="cats">
      {#each v.categories as cv}
        <button class="card catc" onclick={() => showCategory(cv.id)}>
          <div class="row between"><strong>{cv.label}</strong><span class="g grade-{cv.grade}">{cv.grade}</span></div>
          <div class="n">{cv.score >= 0 ? cv.score : '—'}<span class="muted small">{cv.score >= 0 ? ' / 100' : ''}</span></div>
          <div class="bar"><div class="g-{cv.grade}" style="width:{Math.max(cv.score, 0)}%"></div></div>
          <div class="small muted">{t('gui.results.cat_counts', { pass: cv.pass, failed: cv.failed })}</div>
        </button>
      {/each}
    </div>
  {:else if tab === 'not_checked'}
    {#if !r.elevated && notChecked.length}<div class="note warn">{t('audit.hint_admin')}</div>{/if}
    {#if notChecked.length === 0}<div class="empty">{t('gui.results.all_checked')}</div>{/if}
    <div class="list">{#each notChecked as it (it.id)}<IssueCard item={it} mode="not_checked" />{/each}</div>
  {:else if tab === 'accepted'}
    {#if accepted.length === 0}<div class="empty">{t('gui.results.no_accepted')}</div>{/if}
    <div class="list">{#each accepted as it (it.id)}<IssueCard item={it} mode="accepted" onrevoke={revoke} />{/each}</div>
  {:else}
    <div class="card"><table><tbody>
      {#each v.host_rows as row}<tr><th>{row.k}</th><td>{row.v}</td></tr>{/each}
      <tr><th>{t('gui.results.duration')}</th><td>{(r.meta.duration_ms / 1000).toFixed(1)} s</td></tr>
      <tr><th>{t('gui.results.tool')}</th><td>Aplomb {r.meta.version}</td></tr>
    </tbody></table></div>
  {/if}
</div>

{#if accepting}
  <Modal title={t('gui.accept.title', { id: accepting.id })} onclose={() => (accepting = null)}>
    <p><strong>{accepting.title}</strong></p>
    <p class="small muted">{t('gui.accept.text')}</p>
    <label class="field"><span>{t('gui.accept.reason')}</span>
      <!-- svelte-ignore a11y_autofocus -->
      <textarea bind:value={reason} autofocus placeholder={t('gui.accept.placeholder')}></textarea>
    </label>
    {#snippet actions()}
      <button class="btn" onclick={() => (accepting = null)}>{t('gui.cancel')}</button>
      <button class="btn primary" disabled={!reason.trim() || busy} onclick={confirmAccept}>{t('gui.accept.confirm')}</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .page { max-width: 1100px; display: grid; gap: 14px }
  .top { display: flex; gap: 26px; align-items: flex-start; padding: 20px 22px }
  .gauge { text-align: center; flex: none }
  .gauge .grade { font-weight: 700; margin-top: 2px }
  .logo { max-height: 48px; max-width: 160px }
  .summary { margin: 10px 0 12px; padding-left: 18px } .summary li { margin: 2px 0 }
  .counts { display: flex; flex-wrap: wrap; gap: 8px }
  .cnt { border: 1px solid var(--line); background: var(--card); border-radius: 8px; padding: 4px 12px; cursor: pointer; font-size: 13px }
  .cnt:hover { background: var(--hover) } .cnt b { font-size: 16px; margin-right: 3px }
  .cnt.critical b { color: var(--crit) } .cnt.warning b { color: var(--warn) } .cnt.info b { color: var(--info) } .cnt.pass b { color: var(--ok) } .cnt.na b { color: var(--na) }
  .cov { margin-top: 12px; max-width: 420px }
  .bar { height: 6px; background: var(--line); border-radius: 6px; overflow: hidden; margin-top: 4px }
  .bar div { height: 100%; background: var(--accent) }
  .bar .g-A { background: var(--g-A) } .bar .g-B { background: var(--g-B) } .bar .g-C { background: var(--g-C) } .bar .g-D { background: var(--g-D) } .bar .g-E { background: var(--g-E) }
  .actions { gap: 8px } .conf :global(svg) { vertical-align: -2px }
  .filters { gap: 8px; margin-bottom: 10px }
  .filters .check { border: 1px solid var(--line); border-radius: 999px; padding: 3px 11px 3px 8px; background: var(--card); font-size: 13px; font-weight: 600 }
  .filters .check.off { opacity: .55; font-weight: 400 }
  .chip-critical { color: var(--crit) } .chip-warning { color: var(--warn) } .chip-info { color: var(--info) }
  .filters .cat { width: auto; min-width: 180px }
  .search { position: relative; min-width: 200px } .search :global(svg) { position: absolute; left: 9px; top: 9px; color: var(--faint) }
  .search input { padding-left: 32px }
  .list { display: grid; gap: 8px }
  .cats { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px }
  .catc { text-align: left; cursor: pointer; display: grid; gap: 4px } .catc:hover { background: var(--hover) }
  .catc .n { font-size: 26px; font-weight: 700 } .catc .g { font-weight: 800; font-size: 18px }
  th { width: 34% }
</style>
