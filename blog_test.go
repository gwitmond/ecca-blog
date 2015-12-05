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
	"net/http/httputil"
	"net/http/httptest"
	"log"
	"errors"
	"os"
	"os/exec"
	"io"
	"io/ioutil"
	"strings"
	"fmt"
	//"encoding/xml"
        "github.com/jteeuwen/go-pkg-xmlx"
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
var nickname = "test-client"
var priv2Key, _ = rsa.GenerateKey(CryptoRand.Reader, 512)
var client2Cert, _ = subca.SignClientCert(nickname, &priv2Key.PublicKey)
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
		Debug: false,  //don't show debugging
	}
}

// Just test to see if the server is running correctly.
func TestHomepage(t *testing.T) {
	_, err := anonClient().Get(https.URL)
	if err != nil { t.Fatal(err) }
}

// Test to see if our client certificate setup is correct
func TestLogin(t *testing.T) {
	anonclient := anonClient()

	u, err := url.Parse(https.URL)
	check(err)
	u.Path="/createblog" // this one requires log in
	resp, err :=anonclient.Get(u.String())
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 Authentication Required. Got %v", resp.StatusCode)
	}

	// Now use client certificate to log in
	regclient := regClient()

	resp, err = regclient.Get(u.String())
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Cannot Log in. Expected 200 Authentication Required. Got %v\n", resp.StatusCode)
	}
}

func TestSubmitRetrieveBlog(t *testing.T) {
	regclient := regClient()

	create, err := url.Parse(https.URL)
	check(err)
	create.Path="/createblog" // this one requires log in

	submitRetrieveBlog := func(blog Blog) bool {
		form :=  url.Values{
			"cn": {blog.Blogger},
			"title": {blog.Title},
			"cleartext": {blog.Text},
			"signature": {blog.Signature}}
		resp, err := regclient.PostForm(create.String(), form)
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()

		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		if resp.StatusCode != 307 {
			t.Fatalf("Error Posting Blog message. Expected 307. Got %#v\n", resp)
		}

		// redirect to Header[Location]
		location := resp.Header.Get("Location")
		t.Logf("Redirect to %v", location)
		redir, err := url.Parse(https.URL)
		check(err)
		redir.Path = location
		resp, err = regclient.Get(redir.String())
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()

		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		if resp.StatusCode != 200 {
			t.Fatalf("Error reading Blog message. Expected 200. Got %#v\n", resp)
		}

		// todo parse xml and get the blog.
		return true
	}
	err = quick.Check(submitRetrieveBlog, &config)
        if err != nil { t.Error(err) }
}

func TestSignVerifyBlog(t *testing.T) {
	regclient := regClient()

	create, err := url.Parse(https.URL)
	check(err)
	create.Path="/createblog" // this one requires log in

	signVerifyBlog := func(blog Blog) bool {
		// Sanitise input
		blog.Blogger = srand(len(blog.Blogger))
		blog.Title = srand(len(blog.Title))
		blog.Text = srand(len(blog.Text))
		blog.Signature = srand(len(blog.Signature))

		// Sign it
		signature, err := Sign(priv2PEM, cert2PEM, blog.Text)
		if err != nil && err.Error() == "Cannot sign empty message" {
			t.Log(err)
			return true // next message.
		}
		check(err) // die on other errors
		blog.Signature = signature // replace that one form the test-generator.

		// Verify the signature
		valid, message := Verify(blog.Text, signature, chainPEM)
		if valid == false {
			t.Fatalf("Verify gave invalid flag. Openssl found it invalid")
		}
		if message != blog.Text {
			t.Fatalf("Message string form Verify (openssl) is not equal to blogtext that has been signed")
		}

		// Now, send the signed message to the server, to read it back and verify again.
		form :=  url.Values{
			"cn": {blog.Blogger},
			"title": {blog.Title},
			"cleartext": {blog.Text},
			"signature": {blog.Signature}}
		resp, err := regclient.PostForm(create.String(), form)
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()
		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		if resp.StatusCode != 307 {
			t.Fatalf("Error Posting Blog message. Expected 307. Got %#v\n", resp)
		}

		// redirect to Header[Location]
		location := resp.Header.Get("Location")
		t.Logf("Redirect to %v", location)
		redir, err := url.Parse(https.URL)
		check(err)
		redir.Path = location
		resp, err = regclient.Get(redir.String())
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()
		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		if resp.StatusCode != 200 {
			t.Fatalf("Error reading Blog message. Expected 200. Got %#v\n", resp)
		}

		// parse xml and get the blog.
		doc := xmlx.New()
                err = doc.LoadStream(resp.Body, nil)
                check(err)
		blogs := doc.SelectNodes("", "blog")
                t.Logf("list of blogs is: %#v\n", blogs)
		if len(blogs) != 1 {
			t.Fatalf("Error. Expect exactly one <blog> entry. Got %v", len(blogs))
		}
		blogtextNode := blogs[0].SelectNode("", "ecca_text")
		signatureNode  := blogs[0].SelectNode("", "ecca_signature")
		blogtext := blogtextNode.Value // may return nil-pointer error
		signature2 := signatureNode.Value

		// validate again to prove clean transmission through the web and back.
		valid, message2 := Verify(blogtext, signature2, chainPEM)
		if valid == false {
			t.Fatalf("Verify gave invalid flag. Openssl found it invalid")
		}
		if message2 != blog.Text {
			t.Fatalf("Message string form Verify (openssl) is not equal to blogtext that has been signed")
		}
		return true
	}
	err = quick.Check(signVerifyBlog, &config)
        if err != nil { t.Error(err) }
}

//****************** Comments **********************************//

func TestSubmitRetrieveComment(t *testing.T) {
	// create a new blog to attach the comments to.
	regclient := regClient()

	create, err := url.Parse(https.URL)
	check(err)
	create.Path="/createblog" // this one requires log in

	form :=  url.Values{
		"cn": {"TestBlogger"},
		"title": {"A Title"},
		"cleartext": {"The message"},
		"signature": {"Ignore this signature."}}
	resp, err := regclient.PostForm(create.String(), form)
	if err != nil { t.Fatal(err)	}
	defer resp.Body.Close()

	t.Logf("page is: %#v\n", resp)
	t.Logf("headers : %#v\n", resp.Header)
	if resp.StatusCode != 307 {
			t.Fatalf("Error Posting Blog message. Expected 307. Got %#v\n", resp)
	}

	// get  redirect to Header[Location] expect /blog/<id>#<commentId>
	bloglocation := resp.Header.Get("Location")
	blogUrl, err := url.Parse(bloglocation)
	check(err)
	blogId := getFirst(blogRE.FindStringSubmatch(blogUrl.Path))
	t.Logf("Posted blog at %v", bloglocation)

	// Submit a comment, anonymous
	anonclient := anonClient()

	submit, err := url.Parse(https.URL)
	check(err)
	submit.Path="/submit-comment" // optional log in. We do both

	submitRetrieveComment := func(comment Comment) bool {
		// Sanitise input
		comment.Blogger = srand(len(comment.Blogger))
		comment.Title = srand(len(comment.Title))
		comment.Text = srand(len(comment.Text))
		comment.Signature = srand(len(comment.Signature))

		form :=  url.Values{
			"blogId": {blogId},
			"title": {comment.Title},
			"cleartext": {comment.Text},
			"signature": {comment.Signature}}
		resp, err := anonclient.PostForm(submit.String(), form)
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()

		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		body, err := ioutil.ReadAll(resp.Body)
		check(err)
		t.Logf("Body is: %v", body)
		if resp.StatusCode != 307 {
			t.Fatalf("Error Posting Comment. Expected 307. Got %#v\n", resp)
		}

		// redirect to Header[Location]
		commLocation := resp.Header.Get("Location")
		commUrl, err := url.Parse(commLocation)
		check(err)
		commentId := commUrl.Fragment
		t.Logf("CommentId is: %v", commentId)

		t.Logf("Redirect to %v", commLocation)
		redir, err := url.Parse(https.URL)
		check(err)
		redir.Path = commLocation
		resp, err = anonclient.Get(redir.String())
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()

		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		if resp.StatusCode != 200 {
			t.Fatalf("Error reading Blog message. Expected 200. Got %#v\n", resp)
		}

		dumpbody, err := httputil.DumpResponse(resp, true)
		check(err)
		t.Logf("Blog with comments is: %v", string(dumpbody))

		// parse xml and get the comment.
		doc := xmlx.New()
                err = doc.LoadStream(resp.Body, nil)
                check(err)
		comments := doc.SelectNodes("", "comment")
                t.Logf("list of comments is: %#v\n", comments)

		for _, comm := range comments {
			t.Logf("comment is: %#v", comm)
			// search for the correct comment
			if comm.As("*", "id") == commentId {
				// test for more
				if comm.SelectNode("", "ecca_author").Value != "anonymous" {
					t.Fatalf("Commenter is not \"anonymous\"")
				}

				if comm.SelectNode("", "ecca_text").Value != comment.Text {
					t.Fatalf("Comment text is not what we submitted")
				}

				if comm.SelectNode("", "ecca_title").Value != comment.Title {
					t.Fatalf("Comment title is not what we submitted")
				}

				return true // found it
			}
		}
		t.Fatalf("Missing comment for %v", commLocation)
		return false
	}
	err = quick.Check(submitRetrieveComment, &config)
	if err != nil { t.Error(err) }
}

// xyzzy
func TestSignVerifyComment(t *testing.T) {
	regclient := regClient()

	// create a new blog to attach the comments to.
	create, err := url.Parse(https.URL)
	check(err)
	create.Path="/createblog" // this one requires log in

	form :=  url.Values{
		"cn": {"A Blogger"},
		"title": {"Test Title"},
		"cleartext": {"Some message"},
		"signature": {"Ignore this signature."}}
	resp, err := regclient.PostForm(create.String(), form)
	if err != nil { t.Fatal(err)	}
	defer resp.Body.Close()

	t.Logf("page is: %#v\n", resp)
	t.Logf("headers : %#v\n", resp.Header)
	if resp.StatusCode != 307 {
			t.Fatalf("Error Posting Blog message. Expected 307. Got %#v\n", resp)
	}

	// get  redirect to Header[Location] expect /blog/<id>#<commentId>
	bloglocation := resp.Header.Get("Location")
	blogUrl, err := url.Parse(bloglocation)
	check(err)
	blogId := getFirst(blogRE.FindStringSubmatch(blogUrl.Path))
	t.Logf("Posted blog at %v", bloglocation)

	// Retrieve blog with comments, anonymous
	anonclient := anonClient()

	submit, err := url.Parse(https.URL)
	check(err)
	submit.Path="/submit-comment" // optional log in. We do both

	signVerifyComment := func(comment Comment) bool {
		// Sanitise input
		comment.Blogger = srand(len(comment.Blogger))
		comment.Title = srand(len(comment.Title))
		comment.Text = srand(len(comment.Text))
		comment.Signature = srand(len(comment.Signature))

		// Sign it
		signature, err := Sign(priv2PEM, cert2PEM, comment.Text)
		if err != nil && err.Error() == "Cannot sign empty message" {
			t.Log(err)
			return true // next message.
		}
		check(err) // die on other errors
		comment.Signature = signature // replace that one form the test-generator.

		// Verify the signature
		valid, message := Verify(comment.Text, signature, chainPEM)
		if valid == false {
			t.Fatalf("Verify gave invalid flag. Openssl found it invalid")
		}
		if message != comment.Text {
			t.Fatalf("Message string form Verify (openssl) is not equal to commenttext that has been signed")
		}

		// Submit it
		form :=  url.Values{
			"blogId": {blogId},
			"title": {comment.Title},
			"cleartext": {comment.Text},
			"signature": {comment.Signature}}
		resp, err := regclient.PostForm(submit.String(), form)
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()

		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		body, err := ioutil.ReadAll(resp.Body)
		check(err)
		t.Logf("Body is: %v", body)
		if resp.StatusCode != 307 {
			t.Fatalf("Error Posting Comment. Expected 307. Got %#v\n", resp)
		}

		// redirect to Header[Location] expect /blog/<blogId>#<commentId>
		commLocation := resp.Header.Get("Location")
		commUrl, err := url.Parse(commLocation)
		check(err)
		commentId := commUrl.Fragment
		t.Logf("CommentId is: %v", commentId)

		t.Logf("Redirect to %v", commLocation)
		redir, err := url.Parse(https.URL)
		check(err)
		redir.Path = commLocation
		resp, err = anonclient.Get(redir.String())
		if err != nil { t.Fatal(err)	}
		defer resp.Body.Close()

		t.Logf("page is: %#v\n", resp)
		t.Logf("headers : %#v\n", resp.Header)
		if resp.StatusCode != 200 {
			t.Fatalf("Error reading Blog message. Expected 200. Got %#v\n", resp)
		}

		dumpbody, err := httputil.DumpResponse(resp, true)
		check(err)
		t.Logf("Blog with comments is: %v", string(dumpbody))

		// parse xml and get the comment.
		doc := xmlx.New()
                err = doc.LoadStream(resp.Body, nil)
                check(err)
		comments := doc.SelectNodes("", "comment")
                t.Logf("list of comments is: %#v\n", comments)

		for _, comm := range comments {
			t.Logf("comment is: %#v", comm)
			// search for the correct comment
			if comm.As("*", "id") == commentId {
				// test for more
				if comm.SelectNode("", "ecca_author").Value != nickname {
					t.Fatalf("Commenter is not \"anonymous\"")
				}

				if comm.SelectNode("", "ecca_text").Value != comment.Text {
					t.Fatalf("Comment text is not what we submitted")
				}

				if comm.SelectNode("", "ecca_title").Value != comment.Title {
					t.Fatalf("Comment title is not what we submitted")
				}

				commenttext := comm.SelectNode("", "ecca_text").Value
				signature2  := comm.SelectNode("", "ecca_signature").Value
				// validate again to prove clean transmission through the web and back.
				valid, message2 := Verify(commenttext, signature2, chainPEM)
				if valid == false {
					t.Fatalf("Verify gave invalid flag. Openssl found it invalid")
				}
				if message2 != comment.Text {
					t.Fatalf("Message string form Verify (openssl) is not equal to commenttext that has been signed")
				}

				return true // found it
			}
		}
		t.Fatalf("Missing comment for %v", commLocation)
		return false
	}
	err = quick.Check(signVerifyComment, &config)
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


// Sign, Verify, run-helper and makeTempfile  are copied from ecca-proxy. They should go somewhere central.

// Sign a message
func Sign(privkeyPEM []byte, certPEM []byte, message string) (string, error) {
        // log.Printf("signing %v\n", message)
        if len(message) == 0 {
                return "", errors.New("Cannot sign empty message")
        }

        keyFileName := makeTempfile("ecca-key-", privkeyPEM)
        defer os.Remove(keyFileName)

        certFileName := makeTempfile("ecca-cert-", certPEM)
        defer os.Remove(certFileName)
        err, stdout, stderr := run(strings.NewReader(message),
                "openssl", "smime", "-sign", "-signer", certFileName,  "-inkey", keyFileName)
        if err != nil {
                return "", errors.New(fmt.Sprintf("Error decrypting message. Openssl says: %s\n", stderr.String()))
        }
        signature := stdout.String()
        return signature, nil
}


// Verify the message
// Return a boolean whether the message is signed by the signature.
func Verify(message string, signature string, caChainPEM []byte) (bool, string) {
        caFilename := makeTempfile("ecca-ca-", caChainPEM)
        defer os.Remove(caFilename)
        // TODO: create template to merge message and signature in a valid openssl smime like format
        err, stdout, stderr := run(strings.NewReader(signature),
                "openssl", "smime", "-verify",  "-CAfile", caFilename)
        if err != nil {
                log.Printf("Error verifying message. Openssl says: %s\n", stderr.String())
                return false, stderr.String() // return error message for now.
        }
        // Note: with openssl smime signing, the true message is in the signature, we return what we get back from openssl
        // TODO: return message == stdout.String(), plus "error message in case it is false"
        return true, stdout.String() // or Bytes()
}

func run(stdin io.Reader, command string, args ... string) (error, bytes.Buffer, bytes.Buffer) {
        runner := exec.Command(command, args...)
        runner.Stdin = stdin
        var stdout bytes.Buffer
        var stderr bytes.Buffer
        runner.Stdout = &stdout
        runner.Stderr = &stderr
        err := runner.Run()
        if err != nil {
                log.Printf("Error with running command: \"%v %v\"\nerror is: %v\nstderr is: %v\n", command, args, err, stderr.String())
        }
        return err, stdout, stderr
}

// make a tempfile with given data.
// return the filename, caller needs to defer.os.Remove it.
func makeTempfile(prefix string, data []byte) string {
        tempFile, err := ioutil.TempFile("", prefix)
        check(err) // die on error
        tempFileName := tempFile.Name()
        tempFile.Write(data)
        tempFile.Close()
        return tempFileName
}
