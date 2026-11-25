package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTemplateParses(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(Template), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Formats) != 4 {
		t.Errorf("formats = %v", c.Formats)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil || c.Technician != "" {
		t.Fatalf("absent : %+v %v", c, err)
	}
	if err := WriteTemplate(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("technician: Ada\nlogo: logo.png\ndisabled_rules:\n  - id: SMB-003\n    reason: copieur\n"), 0o644)
	c, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Technician != "Ada" || c.Accepted()["SMB-003"] != "copieur" || c.LogoPath(dir) != filepath.Join(dir, "logo.png") {
		t.Errorf("%+v", c)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("technician: [\n"), 0o644)
	if _, err := Load(dir); err == nil {
		t.Error("YAML invalide : erreur attendue")
	}
}

func TestIssuerAndLegacyKeys(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("company: Ancienne\nlogo: old.png\n"), 0o644)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer.Company != "Ancienne" || c.Issuer.Logo != "old.png" || c.LegacyCompany != "" || c.LegacyLogo != "" {
		t.Errorf("anciennes clés non reportées : %+v", c)
	}
	out, _ := yaml.Marshal(c)
	if c2 := (Config{}); yaml.Unmarshal(out, &c2) != nil || c2.LegacyCompany != "" || c2.Issuer.Company != "Ancienne" {
		t.Errorf("réécriture : %s", out)
	}

	os.WriteFile(filepath.Join(dir, FileName), []byte("company: Ignorée\nissuer:\n  name: Ada\n  company: Neuve\n  contact: ada@example.com\n  legal: TVA BE0123\n  color: \"#AA3300\"\n  logo: new.png\n"), 0o644)
	c, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer.Company != "Neuve" || c.Issuer.Name != "Ada" || c.Issuer.Color != "#AA3300" || c.LogoPath(dir) != filepath.Join(dir, "new.png") {
		t.Errorf("issuer : %+v", c.Issuer)
	}

	os.WriteFile(filepath.Join(dir, FileName), []byte("issuer:\n  color: \"red;}body{display:none\"\n"), 0o644)
	if c, _ = Load(dir); c.Issuer.Color != "" {
		t.Errorf("couleur invalide acceptée : %q", c.Issuer.Color)
	}
}
