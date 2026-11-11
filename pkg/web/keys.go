package web

import (
	"net/http"
	"os"
	"strings"
	"unicode"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
)

// keyView is what the UI sees about a key. The key itself is never sent
// back to the browser — only whether it is set and its last 4 characters.
type keyView struct {
	config.KeyField
	Set     bool   `json:"set"`
	Masked  string `json:"masked,omitempty"`
	FromEnv bool   `json:"from_env"` // an environment variable overrides the file
}

func mask(v string) string {
	if len(v) <= 8 {
		return "••••"
	}
	return "••••••••" + v[len(v)-4:]
}

func (s *Server) keysView(w http.ResponseWriter) {
	editable := s.ConfigFile != "" && s.Rebuild != nil
	var f config.File
	if s.ConfigFile != "" {
		var err error
		if f, err = config.ReadFile(s.ConfigFile); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	keys := []keyView{}
	for _, kf := range config.KeyFields {
		kv := keyView{KeyField: kf}
		v := f.Get(kf.ID)
		if e := os.Getenv(kf.Env); e != "" {
			v, kv.FromEnv = e, true
		}
		if v != "" {
			kv.Set, kv.Masked = true, mask(v)
		}
		keys = append(keys, kv)
	}
	writeJSON(w, http.StatusOK, map[string]any{"editable": editable, "config_path": s.ConfigFile, "keys": keys})
}

func (s *Server) keysGet(w http.ResponseWriter, r *http.Request) { s.keysView(w) }

// keysSet updates keys in the config file and hot-reloads the sources.
// Body: {"set": {"virustotal": "..."}, "clear": ["otx"]}. Fields not
// mentioned keep their current value.
func (s *Server) keysSet(w http.ResponseWriter, r *http.Request) {
	if s.ConfigFile == "" || s.Rebuild == nil {
		writeErr(w, http.StatusForbidden, "keys cannot be changed from the UI in this mode")
		return
	}
	var req struct {
		Set   map[string]string `json:"set"`
		Clear []string          `json:"clear"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	f, err := config.ReadFile(s.ConfigFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	changed := 0
	for _, id := range req.Clear {
		if !f.Set(id, "") {
			writeErr(w, http.StatusBadRequest, "unknown key: "+id)
			return
		}
		changed++
	}
	for id, v := range req.Set {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > 512 || strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			writeErr(w, http.StatusBadRequest, id+": a key cannot contain spaces or line breaks — something extra may have been copied")
			return
		}
		if !f.Set(id, v) {
			writeErr(w, http.StatusBadRequest, "unknown key: "+id)
			return
		}
		changed++
	}
	if changed == 0 {
		writeErr(w, http.StatusBadRequest, "no key to change")
		return
	}
	if err := config.WriteFile(s.ConfigFile, f); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not write config: "+err.Error())
		return
	}
	next := s.Rebuild(config.Keys(f))
	s.mu.Lock()
	s.Base = next
	s.ConfigPath = s.ConfigFile
	s.mu.Unlock()
	s.keysView(w)
}
