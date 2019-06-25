package config

import log "github.com/sirupsen/logrus"
import "github.com/BurntSushi/toml"

type webServer struct {
	IP           string
	Port         int
	CertFilename string
	KeyFilename  string
	CSRFilename  string
}

type cloudflareCreds struct {
	API_Email string
	API_Key   string
}

type Config struct {
	Domain          string
	Hostname        string
	Interface       string
	CloudflareCreds cloudflareCreds
	WebServer       webServer
}

func NewConfig(configFile string) (cfg Config, err error) {
	err = cfg.parseFile(configFile)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (cfg *Config) parseFile(configFile string) error {
	if _, err := toml.DecodeFile(configFile, &cfg); err != nil {
		return err
	}
	return nil
}

func (cfg Config) Dump() {
	log.Print("Dumping configuration information")
	log.Printf("Cloudflare user: %s", cfg.CloudflareCreds.API_Email)
	log.Printf("Cloudflare key: %s", cfg.CloudflareCreds.API_Key)
	log.Printf("Domain: %s", cfg.Domain)
	log.Printf("Hostname: %s", cfg.Hostname)
	log.Printf("Interface: %s", cfg.Interface)

	log.Printf("Web server running on IP: %s", cfg.WebServer.IP)
	log.Printf("Web server running on port: %d", cfg.WebServer.Port)
	log.Printf("Certificate filename: %d", cfg.WebServer.CertFilename)
	log.Printf("Private key filename: %d", cfg.WebServer.KeyFilename)
	log.Printf("CSR filename: %d", cfg.WebServer.CSRFilename)
}
