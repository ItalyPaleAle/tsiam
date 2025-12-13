package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	yaml "sigs.k8s.io/yaml/goyaml.v3"

	"github.com/italypaleale/tsiam/pkg/utils"
)

const configFileEnvVar = "TSIAM_CONFIG"

func LoadConfig() error {
	// Get the path to the config.yaml
	// First, try with the TSIAM_CONFIG env var
	configFile := os.Getenv(configFileEnvVar)
	if configFile != "" {
		exists, _ := utils.FileExists(configFile)
		if !exists {
			return NewConfigError("Environmental variable "+configFileEnvVar+" points to a file that does not exist", "Error loading config file")
		}
	} else {
		// Look in the default paths
		// Note: It's .yaml not .yml! https://yaml.org/faq.html (insert "it's leviOsa, not levioSA" meme)
		configFile = FindConfigFile("config.yaml", ".", "~/.tsiam", "/etc/tsiam")
		if configFile == "" {
			// Ok, if you really, really want to use ".yml"....
			configFile = FindConfigFile("config.yml", ".", "~/.tsiam", "/etc/tsiam")
		}

		// Config file not found
		if configFile == "" {
			return NewConfigError("Could not find a configuration file config.yaml in the current folder, '~/.tsiam', or '/etc/tsiam'", "Error loading config file")
		}
	}

	// Load the configuration
	// Note that configFile can be empty
	cfg := Get()
	err := loadConfigFile(cfg, configFile)
	if err != nil {
		return NewConfigError(err, "Error loading config file")
	}
	cfg.SetLoadedConfigPath(configFile)

	return nil
}

// Loads the configuration from a file and from the environment.
// "dst" must be a pointer to a struct.
func loadConfigFile(dst any, filePath string) error {
	f, err := os.Open(filePath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed to open config file '%s': %w", filePath, err)
	}
	defer f.Close() //nolint:errcheck

	yamlDec := yaml.NewDecoder(f)
	yamlDec.KnownFields(true)
	err = yamlDec.Decode(dst)
	if err != nil {
		return fmt.Errorf("failed to decode config file '%s': %w", filePath, err)
	}

	return nil
}

func FindConfigFile(fileName string, searchPaths ...string) string {
	for _, path := range searchPaths {
		if path == "" {
			continue
		}

		p, _ := homedir.Expand(path)
		if p != "" {
			path = p
		}

		search := filepath.Join(path, fileName)
		exists, _ := utils.FileExists(search)
		if exists {
			return search
		}
	}

	return ""
}
