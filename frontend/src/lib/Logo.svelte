<script lang="ts">
  // Fil à plomb : un fil vertical et son plomb.
  let { size = 28 }: { size?: number } = $props()
</script>

<svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
  <rect x="4" y="4" width="56" height="56" rx="14" fill="#2f6fde" />
  <path d="M20 14h24" stroke="#fff" stroke-width="4" stroke-linecap="round" />
  <path d="M32 14v16" stroke="#fff" stroke-width="2.5" />
  <path d="M32 29l9 9-9 14-9-14z" fill="#fff" />
</svg>
