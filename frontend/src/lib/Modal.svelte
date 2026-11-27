<script lang="ts">
  import type { Snippet } from 'svelte'
  let { title, onclose, children, actions }: { title: string; onclose: () => void; children: Snippet; actions: Snippet } = $props()
  function key(e: KeyboardEvent) { if (e.key === 'Escape') onclose() }
</script>

<svelte:window onkeydown={key} />
<div class="back" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) onclose() }}>
  <div class="dlg card" role="dialog" aria-modal="true" aria-label={title}>
    <h2>{title}</h2>
    <div class="body">{@render children()}</div>
    <div class="row actions">{@render actions()}</div>
  </div>
</div>

<style>
  .back { position: fixed; inset: 0; background: rgba(15, 19, 28, .45); display: grid; place-items: center; z-index: 50 }
  .dlg { width: min(560px, 92vw); padding: 20px 22px }
  .body { margin: 6px 0 16px }
  .actions { justify-content: flex-end }
</style>
