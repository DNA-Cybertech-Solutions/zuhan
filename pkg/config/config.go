// Package config loads API keys from a JSON file and environment variables.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// File is the on-disk config format.
type File struct {
	VirusTotal     string `json:"virustotal"`
	AbuseIPDB      string `json:"abuseipdb"`
	OTX            string `json:"otx"`
	AbuseCH        string `json:"abusech"`
	GreyNoise      string `json:"greynoise"`
	HybridAnalysis string `json:"hybrid_analysis"`
}

// EnvVars maps each key to the environment variable that overrides it.
var EnvVars = map[string]string{
	"virustotal":    "VT_API_KEY",
	"abuseipdb":     "ABUSEIPDB_API_KEY",
	"otx":           "OTX_API_KEY",
	"abusech":       "ABUSECH_API_KEY",
	"greynoise":     "GREYNOISE_API_KEY",
	"hybrid":        "HYBRID_API_KEY",
	"malwarebazaar": "ABUSECH_API_KEY",
	"threatfox":     "ABUSECH_API_KEY",
	"urlhaus":       "ABUSECH_API_KEY",
}

// AppDir is the per-user settings folder name.
const AppDir = "zuhan"

// legacyDir is the folder used before the project was renamed to ZUHAN.
const legacyDir = "iocscan"

// DefaultPath is ~/.config/zuhan/config.json (or the OS equivalent).
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "zuhan.json"
	}
	return filepath.Join(dir, AppDir, "config.json")
}

// MigrateLegacy copies config.json and iocdb.json from the old
// ~/.config/iocscan folder into ~/.config/zuhan the first time ZUHAN runs.
// Nothing is copied if the new folder already has either file, and the old
// folder is left untouched. It returns the files it copied.
func MigrateLegacy() ([]string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, nil
	}
	oldDir, newDir := filepath.Join(base, legacyDir), filepath.Join(base, AppDir)
	names := []string{"config.json", "iocdb.json"}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(newDir, n)); err == nil {
			return nil, nil // already set up
		}
	}
	var copied []string
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(oldDir, n))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return copied, err
		}
		if err := os.MkdirAll(newDir, 0o700); err != nil {
			return copied, err
		}
		dst := filepath.Join(newDir, n)
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return copied, err
		}
		copied = append(copied, dst)
	}
	return copied, nil
}

// DefaultDBPath is the local IOC list next to the config file.
func DefaultDBPath() string {
	return filepath.Join(filepath.Dir(DefaultPath()), "iocdb.json")
}

// DBPath resolves the IOC list location:
// explicit flag > ZUHAN_DB > IOCSCAN_DB (legacy) > default.
func DBPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	for _, env := range []string{"ZUHAN_DB", "IOCSCAN_DB"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return DefaultDBPath()
}

// KeyField describes one API key slot in the config file.
type KeyField struct {
	ID    string `json:"id"`    // JSON field name in the config file
	Label string `json:"label"` // human name
	Env   string `json:"env"`   // overriding environment variable
	URL   string `json:"url"`   // where to get a key
	Note  string `json:"note,omitempty"`
}

// KeyFields lists every key, in display order.
var KeyFields = []KeyField{
	{"virustotal", "VirusTotal", "VT_API_KEY", "https://www.virustotal.com/gui/my-apikey", ""},
	{"abusech", "abuse.ch", "ABUSECH_API_KEY", "https://auth.abuse.ch/", "one key for MalwareBazaar, ThreatFox and URLhaus"},
	{"abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "https://www.abuseipdb.com/account/api", ""},
	{"otx", "AlienVault OTX", "OTX_API_KEY", "https://otx.alienvault.com/settings", "optional — works without a key, with lower limits"},
	{"hybrid_analysis", "Hybrid Analysis", "HYBRID_API_KEY", "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab", ""},
	{"greynoise", "GreyNoise", "GREYNOISE_API_KEY", "https://viz.greynoise.io/account/api-key", "optional — works without a key"},
}

// Get returns the stored value of a key field.
func (f File) Get(id string) string {
	switch id {
	case "virustotal":
		return f.VirusTotal
	case "abuseipdb":
		return f.AbuseIPDB
	case "otx":
		return f.OTX
	case "abusech":
		return f.AbuseCH
	case "greynoise":
		return f.GreyNoise
	case "hybrid_analysis":
		return f.HybridAnalysis
	}
	return ""
}

// Set stores a key field value; returns false for an unknown id.
func (f *File) Set(id, v string) bool {
	switch id {
	case "virustotal":
		f.VirusTotal = v
	case "abuseipdb":
		f.AbuseIPDB = v
	case "otx":
		f.OTX = v
	case "abusech":
		f.AbuseCH = v
	case "greynoise":
		f.GreyNoise = v
	case "hybrid_analysis":
		f.HybridAnalysis = v
	default:
		return false
	}
	return true
}

// Resolve returns the config path to use: the explicit one or the default.
func Resolve(path string) string {
	if path == "" {
		return DefaultPath()
	}
	return path
}

// ReadFile reads a config file; a missing file yields an empty File.
func ReadFile(path string) (File, error) {
	var f File
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("config %s: %w", path, err)
	}
	return f, nil
}

// WriteFile atomically writes f to path with 0600 permissions.
func WriteFile(path string, f File) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(append(b, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// Keys turns a File into source keys, applying environment overrides.
func Keys(f File) sources.Keys {
	return sources.Keys{
		VirusTotal:     env("VT_API_KEY", f.VirusTotal),
		AbuseIPDB:      env("ABUSEIPDB_API_KEY", f.AbuseIPDB),
		OTX:            env("OTX_API_KEY", f.OTX),
		AbuseCH:        env("ABUSECH_API_KEY", f.AbuseCH),
		GreyNoise:      env("GREYNOISE_API_KEY", f.GreyNoise),
		HybridAnalysis: env("HYBRID_API_KEY", f.HybridAnalysis),
	}
}

// Load reads keys from path (or the default path) and applies env overrides.
// It returns the path actually read ("" if the default file does not exist).
// A missing default file is not an error; a missing explicit file is.
func Load(path string) (sources.Keys, string, error) {
	explicit := path != ""
	path = Resolve(path)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return Keys(File{}), "", nil
		}
		return sources.Keys{}, path, err
	}
	f, err := ReadFile(path)
	if err != nil {
		return sources.Keys{}, path, err
	}
	return Keys(f), path, nil
}

// WriteTemplate creates an empty config file with 0600 permissions.
func WriteTemplate(path string) error {
	path = Resolve(path)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	return WriteFile(path, File{})
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
