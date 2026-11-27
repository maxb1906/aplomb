// Traductions de l'interface : elles viennent de assets/i18n/<langue>.json
// (Go), comme celles de la ligne de commande et du rapport. Aucune chaîne
// affichée n'est écrite en dur ici : tout passe par t('clé').
let strings = $state<Record<string, string>>({})
let lang = $state('fr')

export function setStrings(l: string, s: Record<string, string>) {
  lang = l
  strings = s
  document.documentElement.lang = l
}

export function currentLang() { return lang }

// t traduit key et remplace les variables {nom}.
export function t(key: string, params?: Record<string, string | number>): string {
  let s = strings[key] ?? key
  if (params) for (const [k, v] of Object.entries(params)) s = s.split('{' + k + '}').join(String(v))
  return s
}

export function fmtDate(iso: string, withTime = true): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  const opts: Intl.DateTimeFormatOptions = withTime
    ? { dateStyle: 'medium', timeStyle: 'short' }
    : { dateStyle: 'medium' }
  return new Intl.DateTimeFormat(lang === 'en' ? 'en-GB' : 'fr-FR', opts).format(d)
}
