package interop

/*
General stuff for creating private keys and CSRs. Shared
between server and client as the server needs it to create
its own certificate on start up.
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"os"
)

import log "github.com/sirupsen/logrus"

const BIT_SIZE = 2048

func GeneratePrivateKey(fileName string) (*rsa.PrivateKey, error) {
	outFile, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("Failed to create private key file, error: ", err)
	}
	defer outFile.Close()

	keyBytes, _ := rsa.GenerateKey(rand.Reader, BIT_SIZE)
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyBytes),
	}

	err = pem.Encode(outFile, privateKey)
	if err != nil {
		log.Fatalf("Failed to save private key file, error: ", err)
	}
	return keyBytes, nil
}

func GenerateCSR(filename string, domainName string, keyBytes *rsa.PrivateKey) ([]byte, error) {
	outFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create CSR file, error: ", err)
	}
	defer outFile.Close()

	subj := pkix.Name{
		CommonName:         domainName,
		Country:            []string{"GB"},
		Province:           []string{""},
		Locality:           []string{"The Internet"},
		Organization:       []string{"DigiNinja"},
		OrganizationalUnit: []string{"Hacking"},
	}
	rawSubj := subj.ToRDNSequence()

	/*
		// Email address now allowed on this type of certificate

		var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
		emailAddress := "robin@digi.ninja"
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: emailAddress},
		})
	*/
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
		//EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	// csrBytes is in DER format
	// https://golang.org/pkg/crypto/x509/#CreateCertificateRequest

	// Don't need to write this to disk as I return the CSR as a []byte which is
	// then used rather than reloading anything from the file. Uncomment
	// this to save it to help with debugging.

	var csr = &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	err = pem.Encode(outFile, csr)
	if err != nil {
		log.Fatalf("Failed to save CSR file, error: ", err)
	}

	return csrBytes, nil
}

// https://golang.org/src/crypto/x509/example_test.go

func LoadX509KeyPair(certFile, keyFile string) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey, *error) {
	// The file should contain the CA certificate followed by the site certificate
	cf, e := ioutil.ReadFile(certFile)
	if e != nil {
		log.Debugf("Error loading the certificate file, error:", e.Error())
		return nil, nil, nil, &e
	}

	kf, e := ioutil.ReadFile(keyFile)
	if e != nil {
		log.Debugf("Error loading the private key file, error:", e.Error())
		return nil, nil, nil, &e
	}

	log.Debug("Decoding the first part of the file, should be the CA")
	caBlock, rest := pem.Decode(cf)

	var certBlock *pem.Block
	if rest != nil {
		log.Debug("Decoding the second part of the file, should be the site certificate")
		certBlock, rest = pem.Decode(rest)
	} else {
		log.Debug("Only one certificate in the file")
		return nil, nil, nil, &e
	}

	log.Debug("Decoding the private key")
	keyBlock, _ := pem.Decode(kf)

	if keyBlock == nil {
		log.Debug("Private key came back nil")
		return nil, nil, nil, &e
	}

	ca, e := x509.ParseCertificate(caBlock.Bytes)
	if e != nil {
		log.Debug("Error parsing CA: %s", e.Error())
		return nil, nil, nil, &e
	}

	cert, e := x509.ParseCertificate(certBlock.Bytes)
	if e != nil {
		log.Debug("Error parsing certificate: %s", e.Error())
		return nil, nil, nil, &e
	}

	key, e := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if e != nil {
		log.Debug("Error parsing private key: %s", e.Error())
		return nil, nil, nil, &e
	}
	return cert, ca, key, nil
}

/*
func main() {
	log.SetLevel(log.DebugLevel)
	ca, cert, key := LoadX509KeyPair("cert.pem", "private.key")

	fmt.Println("Certificate Stuff")
	// https://golang.org/pkg/crypto/x509/#Certificate
	fmt.Printf("CA DNS Names%s\n", ca.DNSNames)
	fmt.Println("Certificate DNS Names")
	for _, name := range cert.DNSNames {
		fmt.Printf("\t%s\n", name)
	}
	fmt.Printf("Not Valid After: %s\n", cert.NotAfter)

	// https://golang.org/pkg/crypto/rsa/#PrivateKey
	fmt.Println("Private Key Stuff")
	fmt.Printf("Exponent:\n")
	fmt.Println(key.D)
}
*/
