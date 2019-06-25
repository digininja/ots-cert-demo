package main

import (
	"fmt"
	"net/http"
)
import log "github.com/sirupsen/logrus"

func HelloServer(w http.ResponseWriter, req *http.Request) {
	log.Debug("Responding to a request")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Congratulations, you should be viewing this over HTTPS on your custom domain.\n"))
}

func StartWebServer(hostname string, port int) {
	listenOn := fmt.Sprintf("%s:%d", hostname, port)
	log.Debug("Starting the web server")
	log.Printf("Setup complete, browse to https://%s", listenOn)
	http.HandleFunc("/", HelloServer)
	err := http.ListenAndServeTLS(listenOn, Cfg.CertFilename, Cfg.KeyFilename, nil)
	log.Debugf("Certificate filename: %s", Cfg.CertFilename)
	log.Debugf("Private key filename: %s", Cfg.KeyFilename)
	if err != nil {
		log.Fatalf("There was a problem starting the web server, error: ", err)
	}
}
