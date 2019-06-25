package config

import log "github.com/sirupsen/logrus"
import "github.com/BurntSushi/toml"

type webServer struct {
	Port int
}

type Config struct {
	ClientRegistrationURL string
	CertificateRequestURL string
	Interface             string
	CertFilename          string
	KeyFilename           string
	CSRFilename           string
	WebServer             webServer
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
	log.Printf("Client Registration URL: %s", cfg.ClientRegistrationURL)
	log.Printf("Certificate Request URL: %s", cfg.CertificateRequestURL)
	log.Printf("Interface: %s", cfg.Interface)

	log.Printf("Web server running on port: %d", cfg.WebServer.Port)

	log.Printf("Certificate filename: %d", cfg.CertFilename)
	log.Printf("Private key filename: %d", cfg.KeyFilename)
	log.Printf("CSR filename: %d", cfg.CSRFilename)
}
