package interop

import (
	"encoding/json"
	"fmt"
)

import log "github.com/sirupsen/logrus"

const Version = "1.0"

const Banner = "\n  _____ _____ _____   _____           _   \n |  _  |_   _/  ___| /  __ \\         | |  \n | | | | | | \\ `--.  | /  \\/ ___ _ __| |_ \n | | | | | |  `--. \\ | |    / _ \\ '__| __|\n \\ \\_/ / | | /\\__/ / | \\__/\\  __/ |  | |_ \n  \\___/  \\_/ \\____/   \\____/\\___|_|   \\__|\n\nA project by Robin Wood - https://digi.ninja/blog/ots_tls_cert.php\n\n"

type JSONMessage struct {
}

func (r JSONMessage) Marshall() string {
	js, err := json.Marshal(r)
	log.Debugf("From the marshall call: %s", js)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error marshalling the JSON request: %s", err.Error()))
	}
	s := string(js[:])
	return s
}

/*
func (r RegClient) Unmarshall(s string) (error, regClient) {
	err := json.NewDecoder(s).Decode(&regClient)

	// error doesn't seem to do much. It DOES NOT pick up on fields that have been missed
	// see https://github.com/golang/go/issues/10140 and https://stackoverflow.com/questions/19633763/unmarshaling-json-in-golang-required-field
	if err != nil {
		log.Printf("There was an error decoding the JSON: %s", err)
		return errors.New(fmt.Sprintf("There was an error decoding the JSON: %s", err))
	} else {

		var regClient RegClient
		return nil, regClient
	}
}
*/

type RegClientRequest struct {
	JSONMessage
	ClientID string
	IP       string
}

func (r RegClientResponse) Marshall() string {
	js, err := json.Marshal(r)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error marshalling the JSON request: %s", err.Error()))
	}
	s := string(js[:])
	return s
}

type RegClientResponse struct {
	Success  bool
	Message  string
	Hostname string
}

type CertificateRequest struct {
	JSONMessage
	CSR      []byte
	ClientID string
}

type CertificateResponse struct {
	JSONMessage
	Success      bool
	Certificates [][]byte
	Message      string
}
