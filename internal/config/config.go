package config

import (
	"encoding/json"
	"log"
	"os"
)

type Configuration struct {
	Host      string  `json:"Host"`
	ProxyPort int     `json:"ProxyPort"`
	Filters   Filters `json:"filters"`
	Logging   Logging `json:"logging"`
}

type Logging struct {
	LogMatchesOnly bool `json:"log_matches_only"`
}

type Filters struct {
	Enabled             bool     `json:"enabled"`
	DomainPatterns      []string `json:"domain_patterns"`
	ResponseContentType []string `json:"response_content_type"`
}

func (c *Configuration) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(data, c); err != nil {
		return err
	}

	log.Printf("Config loaded")
	return nil
}
