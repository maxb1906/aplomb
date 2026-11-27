<script lang="ts">
  let { score, grade, size = 132 }: { score: number; grade: string; size?: number } = $props()
  const r = 52
  const c = 2 * Math.PI * r
  let dash = $derived(score >= 0 ? (c * score) / 100 : 0)
</script>

<svg width={size} height={size} viewBox="0 0 120 120" role="img" aria-label={score >= 0 ? `${score}/100 ${grade}` : '—'}>
  <circle cx="60" cy="60" r={r} fill="none" stroke="var(--line)" stroke-width="11" />
  {#if score >= 0}
    <circle cx="60" cy="60" r={r} fill="none" stroke={`var(--g-${grade})`} stroke-width="11" stroke-linecap="round"
      stroke-dasharray={`${dash} ${c}`} transform="rotate(-90 60 60)" style="transition: stroke-dasharray .6s ease" />
  {/if}
  <text x="60" y="58" text-anchor="middle" font-size="30" font-weight="700" fill="var(--ink)">{score >= 0 ? score : '—'}</text>
  <text x="60" y="80" text-anchor="middle" font-size="13" fill="var(--muted)">/ 100</text>
</svg>
