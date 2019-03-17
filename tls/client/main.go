package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	roots := x509.NewCertPool()

	rootCert, err := ioutil.ReadFile("../certs/1_root/certs/ca.cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	ok := roots.AppendCertsFromPEM(rootCert)
	if !ok {
		panic("failed to parse root certificate")
	}

	tlsConf := &tls.Config{RootCAs: roots}

	tr := &http.Transport{TLSClientConfig: tlsConf}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8433")
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(data))
}
