// Eccentric Authentication Blog site
//
// Create a blog site that allows bloggers to establish a reputation (good or bad) based upon what they write.
// Note, everything anyone writes is signed by their private key.
// Unless one writes as Anonymous Coward.

// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.


// Test code.

package main

import (
	"testing"
	"testing/quick"
	"crypto/rsa"
	"crypto/x509"
	"crypto/tls"
	"bytes"
	"encoding/pem"
	CryptoRand "crypto/rand"
	MathRand   "math/rand"
	"time"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
	"github.com/gwitmond/eccentric-authentication/utils/camaker" // CA maker tools.
	"github.com/gwitmond/eccentric-authentication/fpca"

	"net/url"
	"net/http"
	"net/http/httptest"
	//"log"
	//"io/ioutil"
)

var config = quick.Config {
	MaxCount: 10,
	Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
}

//*******************************************************************************************************//
// Generate a self signed CA cert & key.
var  caCert, caKey, _ = camaker.GenerateCA("The Root CA", "CA", 768)
var caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

// Create subCA signing the clients
var fpcaCert, fpcaKey, _ = camaker.GenerateFPCA("The FPCA Org", "FPCA-CN", caCert, caKey, 512)
var fpcaCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fpcaCert.Raw})
var subca = &fpca.FPCA{
	Namespace: "testca",
	CaCert: fpcaCert,
	CaPrivKey: fpcaKey,
}

// create the chain certificate
var buf = bytes.NewBuffer(caCertPEM)
var n, _  =  buf.WriteString("\n")
var m, _ =  buf.Write(fpcaCertPEM)
var chainPEM = buf.Bytes()

// generate client key and certificate with FPCA CA
var priv2Key, _ = rsa.GenerateKey(CryptoRand.Reader, 512)
var client2Cert, _ = subca.SignClientCert("test-client", &priv2Key.PublicKey)
var priv2PEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv2Key)})
var  cert2PEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client2Cert})

// set up webserver
var bloghandler = &BlogHandler{
	mux: initServeMux(http.NewServeMux()),
}

var https *httptest.Server

func init() { 	// set server TLS config
	https = httptest.NewUnstartedServer(bloghandler)
	serverCert, serverKey,  err := camaker.GenerateCert("localhost", "127.0.0.1",  caCert, caKey, 512)
	check(err)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	tlsCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	check(err)

	// certpool contains the CAs for client certificate validation
	certPool := x509.NewCertPool()
	certPool.AddCert(fpcaCert)
	certPool.AddCert(caCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth: tls.VerifyClientCertIfGiven,
		//ServerName: "localhost",
		ClientCAs: certPool,
	}
	tlsConf.BuildNameToCertificate()
	https.TLS = tlsConf
	https.StartTLS()
}

// anonClient returns a brand new anonymous client (no client certificates)
func anonClient() *http.Client {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{
			RootCAs: certPool,
			ServerName: "localhost"},
	}
	return &http.Client{Transport: transport}
}

// regClient returns a brand new client with client certificate to log in
// Use the client cert from above
func regClient() *http.Client {
	tlsCert, err := tls.X509KeyPair(cert2PEM, priv2PEM)  // our client certificate
	check(err)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)  // the root ca of the server certificate...
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{
			RootCAs: certPool,
			ServerName: "localhost",
			Certificates: []tls.Certificate{tlsCert},
		},
	}
	return &http.Client{Transport: transport}
}

func init() { // set main.ecca to point to need-register template
	ecca = eccentric.Authentication{
		RegisterURL:  "https://register-cryptoblog.wtmnd.nl:10501/register-pubkey",
		Templates: templates,   //Just copy the templates variable
		Debug: true,  // show debugging
	}
}

// Just test to see if the server is running correctly.
func TestHomepage(t *testing.T) {
	_, err := anonClient().Get(https.URL)
	if err != nil { t.Fatal(err) }
}

func TestLogin(t *testing.T) {
	u, err := url.Parse(https.URL)
	check(err)
	u.Path="/createblog" // this one requires log in
	res, err := anonClient().Get(u.String())
	if err != nil { t.Fatal(err) }
	if res.StatusCode != 401 {
		t.Fatalf("expected 401 Authentication Required. Got %v", res.StatusCode)
	}

	// Now use client certificate to log in
	res, err = regClient().Get(u.String())
	if err != nil { t.Fatal(err) }
	if res.StatusCode != 200 {
		t.Fatalf("Cannot Log in. Expected 200 Authentication Required. Got %v\n", res.StatusCode)
	}
}

func TestSubmitRetrieveBlog(t *testing.T) {
	client := regClient()

	create, err := url.Parse(https.URL)
	check(err)
	create.Path="/createblog" // this one requires log in

	submitRetrieveBlog := func(blog Blog) bool {
		form :=  url.Values{
			"cn": {blog.Blogger},
			"title": {blog.Title},
			"cleartext": {blog.Text},
			"signature": {blog.Signature}}
		res, err := client.PostForm(create.String(), form)
		if err != nil { t.Fatal(err)	}
		t.Logf("page is: %#v\n", res)
		t.Logf("headers : %#v\n", res.Header)
		if res.StatusCode != 307 {
			t.Fatalf("Error Posting Blog message. Expected 307. Got %#v\n", res)
		}
		
		// redirect to Header[Location]
		location := res.Header.Get("Location")
		t.Logf("Redirect to %v", location)
		redir, err := url.Parse(https.URL)
		check(err)
		redir.Path = location
		res, err = client.Get(redir.String())
		if err != nil { t.Fatal(err)	}
		t.Logf("page is: %#v\n", res)
		t.Logf("headers : %#v\n", res.Header)
		if res.StatusCode != 200 {
			t.Fatalf("Error reading Blog message. Expected 200. Got %#v\n", res)
		}

		// todo parse xml and get the blog.
		return true
	}
	err = quick.Check(submitVerifyBlog, &config)
        if err != nil { t.Error(err) }
}


var alpha = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
// generates a random string of expected size
func srand(size int) string {
    buf := make([]byte, size)
    for i := 0; i < size; i++ {
        buf[i] = alpha[MathRand.Intn(len(alpha))]
    }
    return string(buf)
}
