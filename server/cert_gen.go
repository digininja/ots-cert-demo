package main

/*
Considered putting this into the interop module but
it needs some very specific stuff that only the
server side should have access to so decided to keep
it in main
*/

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/acme"
	"time"
)

import log "github.com/sirupsen/logrus"

func GenerateCertificate(csrKeyBytes []byte, fqdn string) ([][]byte, error) {
	log.Debugf("Hostname in certificate generation request: %s", fqdn)

	log.Debug("Generating the Lets Encrypt account key")
	// All the usual account registration prelude
	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: "https://acme-v01.api.letsencrypt.org/directory",
	}

	log.Debugf("Registering the account")
	if _, err := client.Register(context.Background(), &acme.Account{},
		func(tos string) bool {
			log.Debugf("Agreeing to ToS: %s", tos)
			return true
		}); err != nil {
		log.Fatalf("Can't register an ACME account, error: ", err)
	}

	// Authorize a DNS name
	log.Debug("Authorising the account")
	authz, err := client.Authorize(context.Background(), fqdn)
	if err != nil {
		log.Fatalf("Can't authorize, error: ", err)
	}

	log.Debug("Find the DNS challenge for this authorization")
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		log.Fatal("No DNS challenge was present")
	}

	log.Debug("Determine the TXT record values for the DNS challenge")

	txtLabel := "_acme-challenge." + authz.Identifier.Value
	txtValue, _ := client.DNS01ChallengeRecord(chal.Token)
	log.Debugf("Creating record %s with value %s", txtLabel, txtValue)

	CreateOrUpdateDNSRecord("TXT", txtLabel, txtValue)

	// It can take a few seconds from creation to becoming visible
	// so a quick sleep then check it was created

	log.Debug("Sleeping 5 seconds to ensure TXT record is setup correctly")
	time.Sleep(5 * time.Second)
	log.Debug("Sleep over")

	success := false
	for i := 0; i < 3; i++ {
		res := CheckRecord("TXT", txtLabel)
		if res {
			success = true
			break
		}
		log.Debugf("TXT record not yet there, sleeping on retry %d", i)
		time.Sleep(5 * time.Second)
	}

	if !success {
		log.Fatal("TXT record not created")
	}
	log.Debug("TXT Record created and all is good")

	// Accept the challenge, wait for the authorization ...
	if _, err := client.Accept(context.Background(), chal); err != nil {
		log.Fatal("Can't accept challenge: ", err)
	}

	success = false
	for i := 0; i < 3; i++ {
		if _, err = client.WaitAuthorization(context.Background(), authz.URI); err == nil {
			success = true
			break
		}
		log.Debugf("Failed authorization, error: %s", err)
		log.Debugf("Sleeping on retry %d", i)
		time.Sleep(2 * time.Second)
	}
	if !success {
		log.Fatal("Failed authorization")
	}
	ctx := context.TODO()
	certs, url, err := client.CreateCert(ctx, csrKeyBytes, (90 * time.Minute * 60 * 24), true)

	if err != nil {
		log.Fatalf(fmt.Sprintf("Got an error when creating the certificate, error: %s", err))
	}

	log.Debugf("The URL is: %s", url)
	log.Debugf("Certificates returned: %d", len(certs))

	if len(certs) > 0 {
		// Need to return all certs
		return certs, nil
	}

	log.Debug("No certificates returned")
	err = errors.New("No certificates returned")
	return nil, err
}
