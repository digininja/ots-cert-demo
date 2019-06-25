package main

import (
	"encoding/json"
	"fmt"
	"github.com/digininja/ots-cert-demo/interop"
	"github.com/docker/docker/pkg/namesgenerator"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	// The reason for the underscore is described here
	// https://stackoverflow.com/questions/21220077/what-does-an-underscore-in-front-of-an-import-statement-mean
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

import log "github.com/sirupsen/logrus"

/*

To call the server:

It will take the UUID in different formats but convert it to the first one after successfully parsing

curl localhost:8080/register -i -X POST -H "Content-Type: application/json" --data '{"clientID":"eca2450a-482d-4b4b-baa5-9ff0daec19e9"}'
curl localhost:8080/register -i -X POST -H "Content-Type: application/json" --data '{"clientID":"URN:UUID:f47ac10b-58cc-4372-0567-0e02b2c3d479"}'
curl localhost:8080/register -i -X POST -H "Content-Type: application/json" --data '{"clientID":"eca2450a482d4b4bbaa59ff0daec19e9"}'

For now, this will return a UUID:

curl localhost:8080/uuid

This will do a POST and pass id as a POST parameter

curl localhost:8080/form -i -X POST -d "id=123&ss=11"

*/

// uuid stuff https://github.com/google/uuid

type Profile struct {
	Name    string
	Hobbies []string
}

// Good snippets
// https://www.alexedwards.net/blog/golang-response-snippets

func generateHostname() string {
	// This is needed to ensure the random number generated to create
	// the name is actually random
	rand.Seed(time.Now().UTC().UnixNano())
	hostname := namesgenerator.GetRandomName(0)

	// underscore not allowed in the hostname so having to swap for a hyphen
	hostname = strings.Replace(hostname, "_", "-", -1)

	return hostname
}

func writeError(w http.ResponseWriter, msg string) {
	//http.Error(w, msg, http.StatusInternalServerError)
	w.WriteHeader(http.StatusInternalServerError)
	log.Debugf("Returning a 500 to the user: %s", msg)
	w.Write([]byte(msg))
}

type Client struct {
	uuid     string
	hostname string
	ip       string
}

func getClient(uuid string) Client {
	log.Debugf("Loading client from database, UUID: %s", uuid)
	rows, err := database.Query("SELECT uuid, hostname, IP FROM clients WHERE uuid = ?", uuid)
	if err != nil {
		log.Fatalf("Error loading client from database, error: %s", err)
	}
	defer rows.Close()
	var client Client
	row_count := 0
	for rows.Next() {
		err := rows.Scan(&client.uuid, &client.hostname, &client.ip)
		if err != nil {
			log.Fatalf("Error scanning returned rows, error: %s", err)
		}
		log.Debugf("Client found, UUID: %s, Hostname: %s, IP: %s", client.uuid, client.hostname, client.ip)
		row_count++
	}
	log.Debugf("Number of rows returned %d", row_count)
	err = rows.Err()
	if err != nil {
		log.Fatalf("Error accessing database, error: %s", err)
	}

	if row_count > 1 {
		// Should never get here as uuid is a primary key
		log.Fatal("Multiple hits, this shouldn't happen")
	}

	return client
}

func generateCertificate(w http.ResponseWriter, r *http.Request) {
	log.Printf("Call to generate a certificate")

	// Used as a placeholder for the certificate when returning an error
	var emptyBytes [][]byte

	var certificaterRequest interop.CertificateRequest
	err := json.NewDecoder(r.Body).Decode(&certificaterRequest)

	// error doesn't seem to do much. It DOES NOT pick up on fields that have been missed
	// see https://github.com/golang/go/issues/10140 and https://stackoverflow.com/questions/19633763/unmarshaling-json-in-golang-required-field
	if err != nil {
		log.Printf("Invalid request, aborting")
		log.Debugf("There was an error decoding the JSON: %s", err)
		certificateResponse := interop.CertificateResponse{Certificates: emptyBytes, Success: false, Message: fmt.Sprintf("Error decoding the JSON\nError message: %s", err)}
		s := certificateResponse.Marshall()
		writeError(w, s)
		return
	}

	parsedUuid, err := uuid.Parse(certificaterRequest.ClientID)
	if err != nil {
		log.Printf("Invalid request, aborting")
		msg := (fmt.Sprintf("Client ID was not in the expected format: %s", certificaterRequest.ClientID))
		log.Debugf("%s", msg)
		certificateResponse := interop.CertificateResponse{Certificates: emptyBytes, Success: false, Message: msg}
		s := certificateResponse.Marshall()
		writeError(w, s)
		return
	}

	client := getClient(parsedUuid.String())

	if client == (Client{}) {
		log.Printf("Invalid request, aborting")
		log.Debugf("Client not found")
		return
	}
	log.Debugf("Request is for: UUID %s, Hostname %s, IP %s", client.uuid, client.hostname, client.ip)

	certificaterRequest.ClientID = parsedUuid.String()
	log.Debugf("The client ID is: %s", certificaterRequest.ClientID)

	//	log.Printf("The CSR is: %s", string(certificaterRequest.CSR[:]))

	/* write it out for testing
	var csr = &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certificaterRequest.CSR,
	}
	outFile, err := os.Create("test.csr")
	if err != nil {
		log.Panic("Failed to create private key file")
	}
	defer outFile.Close()

	err = pem.Encode(outFile, csr)
	if err != nil {
		log.Fatal("Failed to save CSR file")
	}
	*/

	// Need to read the hostname out of the database, can't trust the entry in the CSR
	// and can't ask the user to send it in

	fqdn := fmt.Sprintf("%s.%s", client.hostname, Cfg.Domain)
	certificates, err := GenerateCertificate(certificaterRequest.CSR, fqdn)

	certificateResponse := interop.CertificateResponse{Certificates: certificates, Success: true, Message: "done"}
	js, err := json.Marshal(certificateResponse)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error marshalling the JSON request, error: %s", err.Error()))
		return
	}
	s := string(js[:])

	log.Print("Certificate generated and being returned to the client")

	fmt.Fprintf(w, s)
}

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		//"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		//"::1/128",        // IPv6 loopback
		//"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func registerClient(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()
	log.Printf("Call to register a client")

	var regClient interop.RegClientRequest
	err := json.NewDecoder(r.Body).Decode(&regClient)

	// error doesn't seem to do much. It DOES NOT pick up on fields that have been missed
	// see https://github.com/golang/go/issues/10140 and https://stackoverflow.com/questions/19633763/unmarshaling-json-in-golang-required-field
	if err != nil {
		log.Printf("Invalid request, aborting")
		log.Debugf("There was an error decoding the JSON: %s", err)
		regClientResponse := interop.RegClientResponse{Hostname: "", Success: false, Message: fmt.Sprintf("Error decoding the JSON\nError message: %s", err)}
		s := regClientResponse.Marshall()
		writeError(w, s)
		return
	}

	parsedUuid, err := uuid.Parse(regClient.ClientID)
	if err != nil {
		msg := (fmt.Sprintf("Client ID was not in the expected format: %s", regClient.ClientID))
		log.Debugf("%s", msg)
		regClientResponse := interop.RegClientResponse{Hostname: "", Success: false, Message: msg}
		s := regClientResponse.Marshall()
		writeError(w, s)
		return
	}
	regClient.ClientID = parsedUuid.String()
	log.Printf("The client ID is: %s", regClient.ClientID)

	/*
		This is an optional check put in here to try to stop the demo system from being
		abused by creating certificates for public facing sites.
	*/
	if !isPrivateIP(net.ParseIP(regClient.IP)) {
		msg := (fmt.Sprintf("The IP address passed in is not private: %s", regClient.IP))
		log.Printf("%s", msg)
		regClientResponse := interop.RegClientResponse{Hostname: "", Success: false, Message: msg}
		s := regClientResponse.Marshall()
		log.Debugf("The marshalled message is: %s", s)
		writeError(w, s)
		return
	}
	regClient.ClientID = parsedUuid.String()
	log.Debugf("The IP address is: %s", regClient.IP)

	row := database.QueryRow("SELECT COUNT(*) FROM clients WHERE uuid=?", regClient.ClientID)
	var count int
	err = row.Scan(&count)
	if err != nil {
		fmt.Fprintf(w, "There was an error checking the database")
		log.Fatal("Error on the scan, error: %s", err)
	}
	// log.Printf("The count is %d", count)
	if count > 0 {
		log.Printf("The client is already registered, aborting")
		regClientResponse := interop.RegClientResponse{Hostname: "", Success: false, Message: "The client with provided UUID is already registered"}
		s := regClientResponse.Marshall()
		writeError(w, s)
		return
	}
	log.Debug("Generating a hostname")
	var hostname string
	for {
		hostname = generateHostname()
		log.Printf("Hostname generated for client: %s", hostname)
		row := database.QueryRow("SELECT COUNT(*) FROM clients WHERE hostname=?", hostname)
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
	log.Debug("Doing the insert")
	_, err = database.Exec("INSERT INTO clients (uuid, hostname, IP) VALUES (?,?,?)", regClient.ClientID, hostname, regClient.IP)

	if err != nil {
		log.Fatalf("Could not insert data into the database, error: %s", err)
	}

	log.Printf("Creating DNS record")
	log.Debugf("Creating A record for %s with IP %s", hostname, regClient.IP)
	fqdn := fmt.Sprintf("%s.%s", hostname, Cfg.Domain)
	CreateOrUpdateDNSRecord("A", fqdn, regClient.IP)

	regClientResponse := interop.RegClientResponse{Hostname: fqdn, Success: true, Message: "done"}
	js, err := json.Marshal(regClientResponse)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error marshalling the JSON request: %s", err.Error()))
		return
	}
	s := string(js[:])

	fmt.Fprintf(w, s)
}

func welcomeMessage(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Hit on /, display welcome message")

	message := fmt.Sprintf("Welcome to the OTS Certificate generator for %s", Cfg.Domain)
	js, err := json.Marshal(message)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error marshalling the JSON request: %s", err.Error()))
		return
	}
	s := string(js[:])

	fmt.Fprintf(w, s)
}

// Set the content type for all requests to JSON
func commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

var mutex = &sync.Mutex{}

func StartWebServer() {
	router := mux.NewRouter()
	// Used to set the content type on all requests
	router.Use(commonMiddleware)

	router.HandleFunc("/get_certificate", generateCertificate).Methods("POST")
	router.HandleFunc("/register", registerClient).Methods("POST")
	router.HandleFunc("/", welcomeMessage).Methods("GET")

	ip := Cfg.WebServer.IP
	port := Cfg.WebServer.Port
	listenOn := fmt.Sprintf("%s:%d", ip, port)
	log.Printf(fmt.Sprintf("Starting web server on: https://%s.%s:%d", Cfg.Hostname, Cfg.Domain, Cfg.WebServer.Port))
	log.Debugf(fmt.Sprintf("Listening on: %s", listenOn))

	err := http.ListenAndServeTLS(listenOn, Cfg.WebServer.CertFilename, Cfg.WebServer.KeyFilename, router)

	if err != nil {
		log.Fatalf("There was a problem starting the web server, error: ", err)
	}

}
