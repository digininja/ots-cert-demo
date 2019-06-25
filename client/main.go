package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem" // needed for debug writing out csr
	"flag"
	"fmt"
	"github.com/digininja/ots-cert-demo/client/config"
	"github.com/digininja/ots-cert-demo/interop"
	"github.com/google/uuid"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)
import log "github.com/sirupsen/logrus"

var mainLogger = log.WithFields(log.Fields{"Owner": "Main"})
var Cfg config.Config
var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

var Usage = func() {
	fmt.Fprintf(CommandLine.Output(), interop.Banner)
	fmt.Fprintf(CommandLine.Output(), fmt.Sprintf("Usage: %s [options]\n", os.Args[0]))
	fmt.Fprintf(CommandLine.Output(), fmt.Sprintf("\nOptions:\n"))

	CommandLine.PrintDefaults()
}

func main() {
	interfaceNamePtr := CommandLine.String("interface", "", "The name of the interface to use if there are multiple")
	debugPtr := CommandLine.String("debugLevel", "", "Debug options, I = Info, D = Full Debug")
	dumpConfigPtr := CommandLine.Bool("dumpcfg", false, "Dump the config file entries")
	configFilePtr := CommandLine.String("config", "ots-cert-client.cfg", "Alternative configuration file")
	versionPtr := CommandLine.Bool("version", false, "")

	CommandLine.Usage = Usage
	CommandLine.Parse(os.Args[1:])

	if *versionPtr {
		fmt.Printf(interop.Banner)
		fmt.Printf("OTS Certificate Demo Client Version %s\n\n", interop.Version)
		os.Exit(1)
	}

	log.Printf(interop.Banner)
	switch strings.ToUpper(*debugPtr) {
	case "I":
		log.SetLevel(log.InfoLevel)
	case "D":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.Debug("Parsing the config file")
	var err error

	// If do a := here, Cfg becomes scoped to this function and so its contents are not available
	// outside it.
	Cfg, err = config.NewConfig(*configFilePtr)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Configuration file error: %s", err.Error()))
	}

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

	log.Debugf("Client registration URL: %s", Cfg.ClientRegistrationURL)
	log.Debugf("Certificate request URL: %s", Cfg.CertificateRequestURL)
	log.Debugf("Certificate filename: %s", Cfg.CertFilename)
	log.Debugf("Private key filename: %s", Cfg.KeyFilename)
	log.Debugf("CSR filename: %s", Cfg.CSRFilename)

	/*
		// To start the web server with an existing certificate/key pair

		StartWebServer("infallible-mayer.ots-cert.space", Cfg.WebServer.Port)
		os.Exit(100)
	*/
	uuid := uuid.New()
	clientID := uuid.String()
	log.Debugf("UUID: %s", clientID)

	regClientRequest := interop.RegClientRequest{ClientID: clientID, IP: ip}
	js, err := json.Marshal(regClientRequest)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error marshalling the JSON request: %s", err.Error()))
		return
	}

	/*
		// From here: https://golang.org/pkg/net/http/
		// If you need to fiddle with connection settings, create this and then use it like:
		// client := &http.Client{Transport: tr}

		tr := &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: true,
		}
	*/

	req, err := http.NewRequest("POST", Cfg.ClientRegistrationURL, bytes.NewBuffer(js))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Could not connect to server, error: %s", err)
	}
	defer resp.Body.Close()

	log.Debugf("Response Status: %s\n", resp.Status)

	log.Debugf("Response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Debugf("Response Body: %s\n", string(body))

	var regClientResponse interop.RegClientResponse
	err = json.Unmarshal(body, &regClientResponse)

	if !regClientResponse.Success {
		log.Fatalf(fmt.Sprintf("Could not register the client, error: %s", regClientResponse.Message))
	}
	log.Printf("The hostname is: %s", regClientResponse.Hostname)

	// Generate the key and CSR and request the certificate

	log.Debug("Generating the private key")
	log.Debugf("Writing private key to: %s", Cfg.KeyFilename)

	privateKeyBytes, err := interop.GeneratePrivateKey(Cfg.KeyFilename)
	if err != nil {
		log.Fatalf("Could not generate the private key: %s", err.Error())
	}
	log.Debug("Generating the CSR")
	csr, err := interop.GenerateCSR(Cfg.CSRFilename, regClientResponse.Hostname, privateKeyBytes)
	if err != nil {
		log.Fatalf("Could not generate the CSR: %s", err.Error())
	}

	certificateRequest := interop.CertificateRequest{ClientID: clientID, CSR: csr}
	js, err = json.Marshal(certificateRequest)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error marshalling the JSON request: %s", err.Error()))
		return
	}

	req, err = http.NewRequest("POST", Cfg.CertificateRequestURL, bytes.NewBuffer(js))
	req.Header.Set("Content-Type", "application/json")

	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	log.Debugf("Response Status: %s\n", resp.Status)
	//log.Printf("response Headers:", resp.Header)
	body, _ = ioutil.ReadAll(resp.Body)
	log.Debugf("Response Body: %s\n", string(body))

	var certificateResponse interop.CertificateResponse
	err = json.Unmarshal(body, &certificateResponse)

	if !certificateResponse.Success {
		log.Fatalf("There was a problem generating the certificate: %s", certificateResponse.Message)
	}
	log.Print("The certificate was generated")
	log.Debugf("Writing the certificate to: %s", Cfg.CertFilename)

	certOut, err := os.Create(Cfg.CertFilename)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", Cfg.CertFilename, err)
	}
	for _, certificate := range certificateResponse.Certificates {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err != nil {
			log.Fatalf("Failed to write data to %s: %s", Cfg.CertFilename, err)
		}
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s, : %s", Cfg.CertFilename, err)
	}
	log.Debug("Wrote certificate")

	StartWebServer(regClientResponse.Hostname, Cfg.WebServer.Port)
}
