package preflight

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// The cluster or cloud a kubectl, helm, gcloud or az command targets when
// its command line names none: what the CLI itself would use, read from its
// local configuration. Nothing here makes a network call. env is the
// command's environment (the hook's, with the command's own assignments);
// read reads a file.

// KubeContext returns the current context of the kubeconfig kubectl and helm
// would load: the files in $KUBECONFIG (the first that sets current-context
// wins, as in kubectl), else ~/.kube/config.
func KubeContext(env map[string]string, read func(string) ([]byte, error)) string {
	files := filepath.SplitList(env["KUBECONFIG"])
	if len(files) == 0 && env["HOME"] != "" {
		files = []string{filepath.Join(env["HOME"], ".kube", "config")}
	}
	for _, f := range files {
		if f == "" {
			continue
		}
		b, err := read(f)
		if err != nil {
			continue
		}
		var kc struct {
			CurrentContext string `yaml:"current-context"`
		}
		if yaml.Unmarshal(b, &kc) == nil && kc.CurrentContext != "" {
			return kc.CurrentContext
		}
	}
	return ""
}

// GCPProject returns the project gcloud would use: CLOUDSDK_CORE_PROJECT,
// else core/project of the active configuration (CLOUDSDK_ACTIVE_CONFIG_NAME
// or the active_config file, "default" without either) in CLOUDSDK_CONFIG or
// ~/.config/gcloud.
func GCPProject(env map[string]string, read func(string) ([]byte, error)) string {
	if p := env["CLOUDSDK_CORE_PROJECT"]; p != "" {
		return p
	}
	dir := env["CLOUDSDK_CONFIG"]
	if dir == "" {
		if env["HOME"] == "" {
			return ""
		}
		dir = filepath.Join(env["HOME"], ".config", "gcloud")
	}
	name := env["CLOUDSDK_ACTIVE_CONFIG_NAME"]
	if name == "" {
		if b, err := read(filepath.Join(dir, "active_config")); err == nil {
			name = strings.TrimSpace(string(b))
		}
	}
	if name == "" {
		name = "default"
	}
	b, err := read(filepath.Join(dir, "configurations", "config_"+name))
	if err != nil {
		return ""
	}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.Trim(line, "[]")
		case section == "core":
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "project" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// AzureSubscription returns the name and id of the default subscription az
// would use, from azureProfile.json in AZURE_CONFIG_DIR or ~/.azure.
func AzureSubscription(env map[string]string, read func(string) ([]byte, error)) (name, id string) {
	dir := env["AZURE_CONFIG_DIR"]
	if dir == "" {
		if env["HOME"] == "" {
			return "", ""
		}
		dir = filepath.Join(env["HOME"], ".azure")
	}
	b, err := read(filepath.Join(dir, "azureProfile.json"))
	if err != nil {
		return "", ""
	}
	var p struct {
		Subscriptions []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			IsDefault bool   `json:"isDefault"`
		} `json:"subscriptions"`
	}
	// az writes the file with a UTF-8 byte order mark.
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &p) != nil {
		return "", ""
	}
	for _, s := range p.Subscriptions {
		if s.IsDefault {
			return s.Name, s.ID
		}
	}
	return "", ""
}
