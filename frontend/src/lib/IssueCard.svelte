<script lang="ts">
  import type { Item } from './types'
  import { t } from './i18n.svelte'
  import { copyText, openURL } from './api'
  import { toast } from './state.svelte'
  import Icon from './Icon.svelte'

  let { item, mode = 'issue', open = false, onaccept, onrevoke }: {
    item: Item; mode?: 'issue' | 'not_checked' | 'accepted' | 'plain'; open?: boolean
    onaccept?: (it: Item) => void; onrevoke?: (it: Item) => void
  } = $props()

  let expanded = $state(false)
  $effect(() => { expanded = open })

  let fixes = $derived((item.findings ?? []).filter((f) => f.remediation))
  async function copy(s: string) {
    toast((await copyText(s)) ? t('gui.copied') : t('gui.copy_failed'), 'ok')
  }
  async function copyAll() {
    await copy(fixes.map((f) => (f.object ? `# ${f.object}\n` : '') + f.remediation).join('\n\n'))
  }
  let edge = $derived(mode === 'issue' ? item.level : mode === 'accepted' ? 'accepted' : 'na')
</script>

<article class="item card edge-{edge}" class:expanded>
  <button class="head" onclick={() => (expanded = !expanded)} aria-expanded={expanded}>
    <span class="chev" class:rot={expanded}><Icon name="chevron" size={14} /></span>
    {#if mode === 'issue'}<span class="badge b-{item.level}">{item.level_label}</span>
    {:else}<span class="badge b-{item.status}">{item.status_label}</span>{/if}
    <span class="title">{item.title}</span>
    <span class="grow"></span>
    {#if item.gpo}<span class="badge b-gpo" title={t('gui.item.gpo_hint')}>GPO</span>{/if}
    {#if (item.findings?.length ?? 0) > 1}<span class="badge b-not_checked">{t('gui.item.objects', { n: item.findings!.length })}</span>{/if}
    <span class="cat muted small">{item.category_label}</span>
    <span class="id mono">{item.id}</span>
  </button>

  {#if mode === 'not_checked' && (item.reason || item.note)}
    <p class="sub muted small">{item.reason}{item.reason && item.note ? ' — ' : ''}{item.note}</p>
  {:else if mode === 'accepted' && item.accepted}
    <p class="sub small"><strong>{t('gui.item.accepted_reason')}</strong> {item.accepted}</p>
  {:else if !expanded && item.summary}
    <p class="sub muted small clamp">{item.summary}</p>
  {/if}

  {#if expanded}
    <div class="body stack">
      {#if item.summary}<p class="selectable">{item.summary}</p>{/if}
      {#if item.detail}<p class="muted small selectable">{item.detail}</p>{/if}
      {#if item.note && mode !== 'not_checked'}<p class="note info">{item.note}</p>{/if}
      {#if item.evidence?.length}
        <div class="ev">{#each item.evidence as e}{e.k} = {e.v}<br />{/each}</div>
      {/if}

      {#if item.findings?.length}
        <div>
          <div class="row between">
            <h3>{t('gui.item.objects_title')}</h3>
            {#if fixes.length > 1}<button class="btn ghost small" onclick={copyAll}><Icon name="script" /> {t('gui.item.copy_all')}</button>{/if}
          </div>
          <ul class="objects">
            {#each item.findings as f}
              <li>
                {#if f.object}<div class="row"><strong class="selectable obj">{f.object}</strong>
                  {#if f.level && f.level !== item.level}<span class="badge b-{f.level}">{t('level.' + f.level)}</span>{/if}
                  {#if f.gpo}<span class="badge b-gpo">GPO</span>{/if}</div>{/if}
                {#if f.evidence?.length}<div class="ev">{#each f.evidence as e}{e.k} = {e.v}<br />{/each}</div>{/if}
                {#if f.remediation && mode === 'issue'}
                  <div class="cmd"><pre>{f.remediation}</pre><button onclick={() => copy(f.remediation!)}>{t('gui.copy')}</button></div>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/if}

      {#if item.impact && mode === 'issue'}<div class="note warn"><strong>{t('gui.item.impact')}</strong> {item.impact}</div>{/if}
      {#if item.gpo && item.gpo_path}<div class="note gpo"><strong>{t('gui.item.gpo')}</strong> {item.gpo_path}</div>{/if}
      {#if item.admin && mode === 'not_checked'}<div class="note info">{t('gui.item.needs_admin')}</div>{/if}

      {#if item.refs?.length}
        <div class="small refs"><span class="muted">{t('gui.item.refs')}</span>
          {#each item.refs as r, i}{#if i > 0}<span class="muted"> · </span>{/if}<a href={r.url} onclick={(e) => { e.preventDefault(); openURL(r.url) }}>{r.name}</a>{/each}
        </div>
      {/if}

      {#if mode === 'issue' && onaccept}
        <div class="row foot"><span class="grow"></span>
          <button class="btn ghost" onclick={() => onaccept?.(item)}><Icon name="lock" /> {t('gui.item.accept')}</button>
        </div>
      {:else if mode === 'accepted' && onrevoke}
        <div class="row foot"><span class="grow"></span>
          <button class="btn ghost" onclick={() => onrevoke?.(item)}><Icon name="undo" /> {t('gui.item.revoke')}</button>
        </div>
      {/if}
    </div>
  {/if}
</article>

<style>
  .item { padding: 0; overflow: hidden; border-left-width: 4px }
  .edge-critical { border-left-color: var(--crit) } .edge-warning { border-left-color: var(--warn) } .edge-info { border-left-color: var(--info) }
  .edge-accepted { border-left-color: var(--warn) } .edge-na { border-left-color: var(--na) }
  .head { display: flex; align-items: center; gap: 9px; width: 100%; border: 0; background: none; padding: 11px 14px; cursor: pointer; text-align: left }
  .head:hover { background: var(--hover) }
  .chev { display: inline-flex; color: var(--faint); transition: transform .15s } .chev.rot { transform: rotate(90deg) }
  .title { font-weight: 600 }
  .id { font-size: 11.5px; color: var(--faint); min-width: 58px; text-align: right }
  .cat { white-space: nowrap }
  .sub { margin: -4px 14px 10px 37px }
  .clamp { display: -webkit-box; -webkit-line-clamp: 1; line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden }
  .body { padding: 2px 16px 14px 37px }
  .objects { list-style: none; margin: 8px 0 0; padding: 0 }
  .objects > li { border-top: 1px dashed var(--line); padding: 9px 0 }
  .obj { word-break: break-all }
  .foot { margin-top: 4px }
  .refs a { white-space: nowrap }
</style>
