package main

import (
	"encoding/json"
	"fmt"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

type SecretEnv struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type EnvFrom struct {
	Secret SecretEnv `json:"secret"`
}

type WebhookConfig struct {
	Provider string             `json:"provider"`
	Envs     *map[string]string `json:"envs"`
	EnvFrom  *EnvFrom           `json:"envFrom"`
}

func loadConfig(cfgJSON *extapi.JSON) (*WebhookConfig, error) {
	cfg := &WebhookConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if cfg.Provider == "" {
		return nil, fmt.Errorf("provider is required")
	}

	if v := cfg.EnvFrom; v != nil {
		if v.Secret.Name == "" {
			return nil, fmt.Errorf("secret name is required")
		}
	} else if cfg.Envs == nil {
		return nil, fmt.Errorf("envs or envFrom is required")
	}

	return cfg, nil
}
