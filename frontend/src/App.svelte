<script lang="ts">
  import { onMount } from 'svelte'
  import { api, emit, errText } from './lib/api'
  import { setStrings, t, currentLang } from './lib/i18n.svelte'
  import { app, toast, type Page } from './lib/state.svelte'
  import Icon from './lib/Icon.svelte'
  import Logo from './lib/Logo.svelte'
  import Toasts from './lib/Toasts.svelte'
  import Audit from './views/Audit.svelte'
  import Results from './views/Results.svelte'
  import History from './views/History.svelte'
  import Settings from './views/Settings.svelte'

  let fatal = $state('')

  onMount(async () => {
    try {
      const b = await api()
      const init = await b.Init()
      setStrings(init.lang, init.strings)
      app.init = init
      if (init.has_current) app.result = await b.Current()
      if (init.config_error) toast(init.config_error, 'error')
      emit('gui:ready')
    } catch (e) {
      fatal = errText(e)
    }
    // Les liens externes ne doivent jamais remplacer l'interface dans la fenêtre.
    document.addEventListener('click', (e) => {
      const a = (e.target as HTMLElement).closest('a[href^="http"]')
      if (a) e.preventDefault()
    })
  })

  async function switchLang(l: string) {
    if (l === currentLang()) return
    const b = await api()
    setStrings(l, await b.Strings(l))
    // Le rapport affiché est remis en forme dans la nouvelle langue.
    if (app.result) app.result = await b.Current()
  }

  let nav = $derived<{ id: Page; icon: string; label: string }[]>([
    { id: 'audit', icon: 'play', label: t('gui.nav.audit') },
    { id: 'results', icon: 'results', label: t('gui.nav.results') },
    { id: 'history', icon: 'history', label: t('gui.nav.history') },
    { id: 'settings', icon: 'settings', label: t('gui.nav.settings') },
  ])
</script>

{#if fatal}
  <div class="fatal"><Logo size={48} /><p>{fatal}</p></div>
{:else if app.init}
  <div class="shell">
    <aside>
      <div class="brand"><Logo /> <div><div class="name">Aplomb</div><div class="tag">{t('gui.tagline')}</div></div></div>
      <nav>
        {#each nav as n}
          <button class:on={app.page === n.id} disabled={n.id === 'results' && !app.result} onclick={() => (app.page = n.id)}>
            <Icon name={n.icon} size={17} /> <span>{n.label}</span>
            {#if n.id === 'results' && app.result}<span class="pill grade-bg-{app.result.score.grade}">{app.result.score.grade}</span>{/if}
            {#if n.id === 'audit' && app.auditing}<span class="spin"></span>{/if}
          </button>
        {/each}
      </nav>
      <div class="grow"></div>
      <div class="machine">
        <div class="host selectable">{app.init.hostname}</div>
        {#if app.init.elevated}
          <div class="elev ok"><Icon name="admin" size={14} /> {t('gui.side.admin')}</div>
        {:else}
          <div class="elev no"><Icon name="shield" size={14} /> {t('gui.side.not_admin')}</div>
        {/if}
      </div>
      <div class="foot">
        <div class="langs">
          {#each app.init.languages as l}
            <button class:on={currentLang() === l} onclick={() => switchLang(l)}>{l.toUpperCase()}</button>
          {/each}
        </div>
        <span class="ver">v{app.init.version}</span>
      </div>
    </aside>
    <main>
      {#if app.page === 'audit'}<Audit />
      {:else if app.page === 'results' && app.result}<Results />
      {:else if app.page === 'history'}<History />
      {:else if app.page === 'settings'}<Settings />
      {/if}
    </main>
  </div>
{/if}
<Toasts />

<style>
  .shell { display: grid; grid-template-columns: 228px 1fr; height: 100% }
  aside { background: var(--side); color: var(--side-ink); display: flex; flex-direction: column; padding: 16px 12px 12px }
  .brand { display: flex; gap: 10px; align-items: center; padding: 2px 6px 18px }
  .name { color: #fff; font-weight: 700; font-size: 17px; letter-spacing: .01em }
  .tag { font-size: 11.5px; color: #8d97a8; line-height: 1.3 }
  nav { display: grid; gap: 2px }
  nav button {
    display: flex; align-items: center; gap: 10px; border: 0; background: none; color: var(--side-ink); text-align: left;
    padding: 8px 10px; border-radius: 8px; cursor: pointer; font-weight: 500;
  }
  nav button:hover:not(:disabled) { background: var(--side-active); color: #fff }
  nav button.on { background: var(--side-active); color: #fff; box-shadow: inset 3px 0 0 var(--accent) }
  nav button:disabled { opacity: .4; cursor: default }
  nav span:nth-child(2) { flex: 1 }
  .pill { font-size: 11px; font-weight: 700; border-radius: 6px; padding: 0 6px; color: #fff }
  .grade-bg-A { background: var(--g-A) } .grade-bg-B { background: var(--g-B) } .grade-bg-C { background: var(--g-C) }
  .grade-bg-D { background: var(--g-D) } .grade-bg-E { background: var(--g-E) } .grade-bg-- { background: var(--na) }
  .machine { border-top: 1px solid #2c3548; padding: 12px 8px 10px; font-size: 12.5px }
  .host { color: #fff; font-weight: 600; word-break: break-all }
  .elev { display: flex; gap: 6px; align-items: center; margin-top: 3px }
  .elev.ok { color: #5fd49a } .elev.no { color: #f5b25e }
  .foot { display: flex; align-items: center; justify-content: space-between; padding: 0 6px }
  .langs { display: flex; gap: 2px; background: #151a26; border-radius: 7px; padding: 2px }
  .langs button { border: 0; background: none; color: #8d97a8; font-size: 11.5px; font-weight: 600; padding: 2px 8px; border-radius: 5px; cursor: pointer }
  .langs button.on { background: var(--side-active); color: #fff }
  .ver { font-size: 11px; color: #6b7588 }
  main { overflow-y: auto; padding: 26px 32px 40px }
  .fatal { height: 100%; display: grid; place-content: center; justify-items: center; gap: 12px; color: var(--muted); text-align: center; padding: 20px }
</style>
