<script lang="ts">
  import { onMount } from 'svelte'
  import { api, errText } from '../lib/api'
  import { t, fmtDate } from '../lib/i18n.svelte'
  import { app, toast } from '../lib/state.svelte'
  import type { Entry } from '../lib/types'
  import Icon from '../lib/Icon.svelte'

  let list = $state<Entry[] | null>(null)
  let host = $state('')
  let hosts = $derived([...new Set((list ?? []).map((e) => e.host))].sort())
  let shown = $derived((list ?? []).filter((e) => !host || e.host === host))

  async function load() {
    try { list = await (await api()).History() } catch (e) { list = []; toast(errText(e), 'error') }
  }
  onMount(load)

  async function show(e: Entry) {
    try {
      app.result = await (await api()).OpenReport(e.path)
      app.page = 'results'
    } catch (err) { toast(errText(err), 'error') }
  }
  async function html(e: Entry) {
    try { await (await api()).OpenPath(e.path.replace(/\.json$/, '.html')) } catch (err) { toast(errText(err), 'error') }
  }
  async function folder() {
    try { await (await api()).OpenDataDir() } catch (err) { toast(errText(err), 'error') }
  }
</script>

<div class="page">
  <header class="row between wrap">
    <div><h1>{t('gui.history.title')}</h1><p class="muted">{t('gui.history.lead')}</p></div>
    <div class="row">
      <button class="btn" onclick={load}><Icon name="refresh" /> {t('gui.refresh')}</button>
      <button class="btn" onclick={folder}><Icon name="folder" /> {t('gui.history.open_dir')}</button>
    </div>
  </header>

  {#if list === null}
    <div class="empty"><span class="spin"></span></div>
  {:else if list.length === 0}
    <div class="empty card">{t('gui.history.empty')}</div>
  {:else}
    {#if hosts.length > 1}
      <div class="row"><select bind:value={host} class="hsel">
        <option value="">{t('gui.history.all_hosts', { n: hosts.length })}</option>
        {#each hosts as h}<option value={h}>{h}</option>{/each}
      </select></div>
    {/if}
    <div class="card tbl">
      <table>
        <thead><tr>
          <th>{t('gui.history.col.host')}</th><th>{t('gui.history.col.date')}</th><th>{t('gui.history.col.score')}</th>
          <th>{t('gui.history.col.issues')}</th><th>{t('gui.history.col.coverage')}</th><th></th>
        </tr></thead>
        <tbody>
          {#each shown as e (e.path)}
            <tr ondblclick={() => show(e)}>
              <td><strong>{e.host}</strong><div class="muted small">{e.os}{e.role ? ' · ' + t('role.' + e.role) : ''}</div></td>
              <td class="nw">{fmtDate(e.collected_at)}{#if !e.elevated}<div class="small warn">{t('gui.history.not_admin')}</div>{/if}</td>
              <td class="nw"><span class="g grade-{e.grade}">{e.grade}</span> <span class="muted">{e.score >= 0 ? e.score : '—'}</span></td>
              <td class="iss nw">
                <span class="badge b-critical">{e.critical}</span><span class="badge b-warning">{e.warning}</span><span class="badge b-info">{e.info}</span>
              </td>
              <td>{e.coverage} %</td>
              <td class="act">
                <button class="btn" onclick={() => show(e)}>{t('gui.history.show')}</button>
                {#if e.has_html}<button class="btn ghost" title={t('gui.results.open_html')} onclick={() => html(e)}><Icon name="external" /></button>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<style>
  .page { max-width: 1100px; display: grid; gap: 16px }
  header p { margin: 4px 0 0 }
  .tbl { padding: 4px 0 } .tbl th:first-child, .tbl td:first-child { padding-left: 18px }
  .g { font-weight: 800; font-size: 16px }
  .iss .badge { margin-right: 4px; min-width: 28px; text-align: center }
  .act { text-align: right; white-space: nowrap }
  .nw { white-space: nowrap }
  .warn { color: var(--warn) }
  .hsel { width: auto; min-width: 220px }
</style>
