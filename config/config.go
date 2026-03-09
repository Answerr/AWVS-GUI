package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config 保存应用程序配置
type Config struct {
	BaseURL   string `json:"base_url"`
	APIKey    string `json:"api_key"`
	ProxyHost string `json:"proxy_host"`
	ProxyPort string `json:"proxy_port"`
	// 测绘引擎 API Keys
	FofaEmail  string `json:"fofa_email"` // 可选（部分 Fofa 账户需要）
	FofaKey    string `json:"fofa_key"`
	ShodanKey  string `json:"shodan_key"`
	HunterKey  string `json:"hunter_key"`
	QuakeKey   string `json:"quake_key"`
	ZoomEyeKey string `json:"zoomeye_key"`
}

func getConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".awvs-client", "config.json")
}

// Load 从磁盘读取配置
func Load() *Config {
	cfg := &Config{
		BaseURL: "https://localhost:3443",
	}
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg
	}
	return cfg
}

// Save 将配置写入磁盘
func (c *Config) Save() error {
	path := getConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
