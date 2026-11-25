# {{t "report.title"}} — {{.R.Host.Name}}

> **{{t "report.confidential"}}**

{{datetime .R.Meta.CollectedAt}}{{if .R.Meta.Technician}} · {{t "report.technician"}} : {{.R.Meta.Technician}}{{end}}{{if .R.Meta.Company}} · {{.R.Meta.Company}}{{end}} · Aplomb {{.R.Meta.Version}}

**{{t "report.score"}} : {{if .HasScore}}{{.R.Score.Score}} / 100{{else}}—{{end}} — {{t "report.grade"}} {{.R.Score.Grade}}** · {{t "report.coverage" "coverage" .R.Score.Coverage}}

## {{t "report.summary"}}

{{range .Summary}}- {{.}}
{{end}}
| {{t "report.category"}} | {{t "report.score"}} | {{t "report.grade"}} |
|---|---|---|
{{range .Categories}}| {{.Label}} | {{if ge .Score 0}}{{.Score}}{{else}}—{{end}} | {{.Grade}} |
{{end}}
## {{t "report.machine"}}

| | |
|---|---|
{{range .HostRows}}| {{md .K}} | {{md .V}} |
{{end}}
## {{t "report.issues"}} ({{len .Issues}})
{{if not .Issues}}
{{t "report.no_issue"}}
{{end}}{{range $it := .Issues}}
### {{.LevelLabel}} — {{.Title}} (`{{.ID}}`)

{{.Summary}}
{{if .Detail}}
*{{.Detail}}*
{{end}}{{if .GPO}}
> {{t "report.gpo_fix"}}{{if .GPOPath}} : {{.GPOPath}}{{end}}
{{end}}{{if .Impact}}
> ⚠ {{.Impact}}
{{end}}{{range .Findings}}{{if .Object}}
- **{{.Object}}**{{if ne .Level $it.Level}} ({{levelLabel .Level}}){{end}}
{{end}}{{if .Remediation}}
```powershell
{{.Remediation}}
```
{{end}}{{end}}{{if .Refs}}
{{t "report.refs"}} : {{range $i, $r := .Refs}}{{if $i}} · {{end}}[{{$r.Name}}]({{$r.URL}}){{end}}
{{end}}{{end}}
{{if .Accepted}}## {{t "report.accepted"}} ({{len .Accepted}})

{{range .Accepted}}- `{{.ID}}` {{.Title}} — {{t "report.justification"}} : {{.Accepted}}
{{end}}
{{end}}{{if .NotChecked}}## {{t "report.not_checked"}} ({{len .NotChecked}})

{{t "report.not_checked_help"}}

{{range .NotChecked}}- `{{.ID}}` {{.Title}} — {{.Reason}}
{{end}}
{{end}}## {{t "report.details"}}
{{range .Categories}}
### {{.Label}}

| | | |
|---|---|---|
{{range .Items}}| `{{.ID}}` | {{md .Title}}{{if .Note}} — {{md .Note}}{{end}} | {{.StatusLabel}}{{if eq .Status "fail"}} · {{.LevelLabel}}{{end}} |
{{end}}{{end}}
---

{{t "report.footer" "version" .R.Meta.Version}}
