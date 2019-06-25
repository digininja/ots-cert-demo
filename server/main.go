package main

/*
References

Example DNS code
https://github.com/cloudflare/cloudflare-go/blob/master/dns_example_test.go

This is the DNS code with the functions and declarations in it
https://github.com/cloudflare/cloudflare-go/blob/master/dns.go

This is the cloudflare API spec
https://api.cloudflare.com/#dns-records-for-a-zone-update-dns-record
*/

import (
	"database/sql"
	"encoding/pem" // needed for debug writing out csr
	"flag"
	"fmt"
	"github.com/digininja/ots-cert-demo/interop"
	"github.com/digininja/ots-cert-demo/server/config"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"strings"
	"time"
)

import log "github.com/sirupsen/logrus"

var database *sql.DB

func initDatabase() {
	log.Debug("Setting up the database")

	var err error
	database, err = sql.Open("sqlite3", "./ots-cert.db")
	if err != nil {
		log.Fatalf("can't connect to the database, error: %s", err)
	}

	log.Debug("Creating the database if required")

	statement, err := database.Prepare("CREATE TABLE IF NOT EXISTS clients (uuid TEXT PRIMARY KEY, hostname TEXT, IP TEXT)")
	statement.Exec()

	if err != nil {
		log.Fatalf("can't create the table, error: %s", err.Error())
	}
}

var Cfg config.Config
var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

var Usage = func() {
	fmt.Fprintf(CommandLine.Output(), interop.Banner)

	fmt.Fprintf(CommandLine.Output(), fmt.Sprintf("Usage: %s [options]\n", os.Args[0]))
	fmt.Fprintf(CommandLine.Output(), fmt.Sprintf("\nOptions:\n"))

	CommandLine.PrintDefaults()
}

func main() {
	var err error

	dumpConfigPtr := CommandLine.Bool("dumpcfg", false, "Dump the config file entries")
	configFilePtr := CommandLine.String("config", "ots-cert-server.cfg", "Alternative configuration file")
	debugPtr := CommandLine.String("debugLevel", "", "Debug options, I = Info, D = Full Debug")
	interfaceNamePtr := CommandLine.String("interface", "", "The name of the interface to use if there are multiple")
	versionPtr := CommandLine.Bool("version", false, "")
	CommandLine.Usage = Usage
	CommandLine.Parse(os.Args[1:])

	if *versionPtr {
		fmt.Printf(interop.Banner)
		fmt.Printf("OTS Certificate Demo Server Version: %s\n\n", interop.Version)
		os.Exit(1)
	}

	switch strings.ToUpper(*debugPtr) {
	case "I":
		log.SetLevel(log.InfoLevel)
	case "D":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.Info(interop.Banner)
	log.Info("Starting the server")

	log.Debug("Parsing the config file")
	Cfg, err = config.NewConfig(*configFilePtr)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Configuration file error: %s", err.Error()))
	}

	log.Debugf("The server will be acting on behalf of the domain: %s", Cfg.Domain)

	if *dumpConfigPtr {
		Cfg.Dump()
		os.Exit(0)
	}

	var interfaceName string

	if Cfg.Interface != "" {
		interfaceName = Cfg.Interface
		log.Debugf("Got the interface %s from the config file", Cfg.Interface)
	}

	if *interfaceNamePtr != "" {
		interfaceName = *interfaceNamePtr
		log.Debugf("Forcing the use of the interface: %s", interfaceName)
	}
	ip := interop.GetIP(interfaceName)

	var hostname string
	var fqdn string

	// This works through the process, if it is not valid
	// at the end, a new certificate is created
	certValid := false

	// Initialise all the Cloudflare stuff here so it can be used to generate a local certificate
	// if required.
	InitCloudflare()

	// Create the database early on so it can be used
	initDatabase()

	if Cfg.Hostname == "" {
		log.Debug("No hostname specified, generating one")
		for {
			hostname = generateHostname()
			log.Printf("Hostname generated: %s", hostname)
			row := database.QueryRow("select count(*) from clients where hostname=?", hostname)
			var count int
			err := row.Scan(&count)
			if err != nil {
				log.Fatalf("Error on the scan, error: %s", err)
			}
			// log.Printf("the count is %d", count)
			if count > 0 {
				log.Debug("Hostname already exists, going around again")
			} else {
				log.Debug("Hostname is unique")
				break
			}
		}

		// This isn't needed by the server but prevents a client from coming in and getting the
		// same hostname.
		uuid := uuid.New()
		s := uuid.String()
		log.Debugf("UUID: %s", s)

		log.Debug("Doing the insert")
		_, err = database.Exec("INSERT INTO clients (uuid, hostname, IP) VALUES (?,?,?)", uuid, hostname, ip)

		if err != nil {
			log.Fatalf("Could not insert data into the database, error: %s", err)
		}

		fqdn = fmt.Sprintf("%s.%s", hostname, Cfg.Domain)
	} else {
		hostname = Cfg.Hostname
		fqdn = fmt.Sprintf("%s.%s", hostname, Cfg.Domain)

		_, certExistsErr := os.Stat(Cfg.WebServer.CertFilename)
		_, keyExistsErr := os.Stat(Cfg.WebServer.KeyFilename)

		if keyExistsErr == nil && certExistsErr == nil {
			// Return params are ca, cert and key
			_, cert, _, err := interop.LoadX509KeyPair(Cfg.WebServer.CertFilename, Cfg.WebServer.KeyFilename)
			// Certificate details are here
			// https://golang.org/pkg/crypto/x509/#Certificate

			if err == nil {
				log.Debug("Found and parsed an existing certificate and key")

				// Should really check for it being valid for a while after start up
				// e.g. 24 hours minimum, but not really needed in this instance
				log.Debugf("Not Valid After: %s\n", cert.NotAfter)
				if time.Now().After(cert.NotAfter) {
					log.Debug("Certificate has expired")
				} else {
					log.Debug("Cert not expired, checking DNS names")
					for _, name := range cert.DNSNames {
						log.Debugf("Name: %s\n", name)
						if name == fqdn {
							log.Debugf("DNS Name in certificate matches hostname for the box")
							// At this point, the cert has not expired and has a DNS
							// entry which matches our host name, looks good to use
							certValid = true
							break
						}
					}
					if !certValid {
						log.Debugf("No matching DNS names found")
					}
				}
			}

		} else {
			if keyExistsErr != nil {
				log.Debug("Can't find private key")
			}
			if certExistsErr != nil {
				log.Debug("Can't find certificate")
			}
		}

	}
	if !certValid {
		log.Printf("No valid certificate found, going to create a new one")

		log.Debugf("Certificate filename: %s", Cfg.WebServer.CertFilename)
		log.Debugf("Private key filename: %s", Cfg.WebServer.KeyFilename)
		log.Debugf("CSR filename: %s", Cfg.WebServer.CSRFilename)

		log.Debug("Generating the private key")
		privateKeyBytes, err := interop.GeneratePrivateKey(Cfg.WebServer.KeyFilename)
		if err != nil {
			log.Fatalf("Could not generate the private key: %s", err.Error())
		}
		log.Debug("Generating the CSR")

		csr, err := interop.GenerateCSR(Cfg.WebServer.CSRFilename, fqdn, privateKeyBytes)
		if err != nil {
			log.Fatalf("Could not generate the CSR: %s", err.Error())
		}

		certificates, err := GenerateCertificate(csr, fqdn)

		log.Debug("Certificate generated, writing it to disk")

		certOut, err := os.Create(Cfg.WebServer.CertFilename)
		if err != nil {
			log.Fatalf("Failed to open %s for writing: %s", Cfg.WebServer.CertFilename, err)
		}
		for _, certificate := range certificates {
			if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err != nil {
				log.Fatalf("Failed to write data to %s: %s", Cfg.WebServer.CertFilename, err)
			}
		}
		if err := certOut.Close(); err != nil {
			log.Fatalf("Error closing %s, : %s", Cfg.WebServer.CertFilename, err)
		}
		log.Debug("Wrote certificate")
	}
	// os.Exit(10)

	log.Printf("Creating DNS record")
	log.Debugf("Creating A record for %s with IP %s", hostname, ip)
	CreateOrUpdateDNSRecord("A", fqdn, ip)

	StartWebServer()
}
