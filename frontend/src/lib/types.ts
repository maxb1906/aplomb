// Formes JSON renvoyées par internal/gui (Go).

export type KV = { k: string; v: string }

export type Finding = { object?: string; level: string; evidence?: KV[]; remediation?: string; gpo?: boolean }

export type Item = {
  id: string; category: string; category_label: string
  status: string; status_label: string; level: string; level_label: string
  title: string; summary?: string; detail?: string; impact?: string; gpo_path?: string
  note?: string; reason?: string; accepted?: string; gpo?: boolean; admin?: boolean
  evidence?: KV[]; findings?: Finding[]; refs?: { name: string; url: string }[]
}

export type CategoryView = { id: string; label: string; score: number; grade: string; pass: number; failed: number; items: Item[] }

export type Counts = {
  pass: number; fail: number; not_checked: number; not_applicable: number; accepted_risk: number
  critical: number; warning: number; info: number
}

export type Score = { score: number; raw_score: number; grade: string; capped: boolean; coverage: number; counts: Counts }

export type Meta = {
  version: string; collected_at: string; generated_at: string; duration_ms: number
  lang: string; profile: string; elevated: boolean; technician?: string; company?: string
}

export type View = {
  lang: string; logo?: string; host_rows: KV[]; summary: string[]
  issues: Item[] | null; accepted: Item[] | null; not_checked: Item[] | null; categories: CategoryView[]; has_score: boolean
}

export type Result = {
  source: 'audit' | 'history'; meta: Meta; score: Score; view: View
  dir: string; files: Record<string, string>; elevated: boolean
}

export type Disabled = { id: string; reason: string; title?: string }

export type Config = {
  technician: string; company: string; logo: string; lang: string; report_lang: string
  profile: string; formats: string[]; disabled: Disabled[] | null
}

export type Init = {
  version: string; lang: string; languages: string[]; strings: Record<string, string>
  can_audit: boolean; elevated: boolean; hostname: string; data_dir: string; sections: string[]
  config: Config; config_error?: string; has_current: boolean
}

export type Entry = {
  path: string; host: string; os: string; role: string; collected_at: string; version: string
  elevated: boolean; score: number; grade: string; coverage: number
  critical: number; warning: number; info: number; has_html: boolean
}

export type Progress = { section: string; label: string; index: number; total: number }
