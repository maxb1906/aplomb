<script lang="ts">
  import { toasts } from './state.svelte'
  import Icon from './Icon.svelte'
</script>

<div class="toasts" aria-live="polite">
  {#each toasts.list as x (x.id)}
    <div class="toast {x.kind}"><Icon name={x.kind === 'ok' ? 'check' : 'alert'} /> <span class="selectable">{x.text}</span></div>
  {/each}
</div>

<style>
  .toasts { position: fixed; right: 18px; bottom: 18px; display: grid; gap: 8px; z-index: 60; max-width: 460px }
  .toast { display: flex; gap: 8px; align-items: flex-start; background: var(--ink); color: var(--bg); padding: 9px 14px; border-radius: 8px; box-shadow: 0 6px 20px rgba(0,0,0,.2); font-size: 13px }
  .toast.error { background: var(--crit); color: #fff }
  .toast :global(svg) { margin-top: 2px }
</style>
