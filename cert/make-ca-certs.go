package main

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/tls"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "errors"
        "io"
	"os"
        "math/big"
        "time"
	"text/template"
	"fmt"
)

// Change the name of your application site. All other names are based upon that.
var sitename = "CryptoBlog.Wtmnd.nl"
var registersitename = "register-" + sitename
var fileprefix = "CryptoBlob" // the prefix for the RootCA and FPCA keys and certificates.

// dependent names. Leave like it is for easy configuration of your site and FPCA.
var RootCAorg = "The Root CA that identifies all that belongs to " + sitename 
var RootCAcn = "RootCA." + sitename
var FPCAorg = "The FPCA for " + sitename
var FPCAcn = "FPCA." + sitename

func main() {
	// Generate a self signed CA cert & key. 
	// This is the Root CA key/cert.
	caCert, caKey, err := generateCA(RootCAorg, RootCAcn)
	handle(err)
	writePair(fileprefix + "RootCA", caCert, caKey)

	// Generate the FPCA Key and certificate that sign the client certificates
	fpcaCert, fpcaKey, err := generateFPCA(FPCAorg, FPCAcn, caCert, caKey)
	handle(err)
	writePair(fileprefix + "FPCA", fpcaCert, fpcaKey)

        // Generate a site key and cert  signed by our RootCA
        siteCert, siteKey, err := generateCert(sitename, caCert, caKey)
        handle(err)
	writePair(sitename, siteCert, siteKey)

        // Generate a FPCA TLS key sign its certificate with our Root CA.
	// So customers can use https to sign up.
        regCert, regKey, err := generateCert(registersitename, caCert, caKey)
        handle(err)
	writePair(registersitename, regCert, regKey)

	// Generate TLSA records with RootCaCert
	genTLSA("_443._tcp." + sitename, caCert)               // sites are signed by the RootCA. 
	genTLSA("_443._tcp." + registersitename, caCert)

	// These form a certificate chain. Not endpoints of tls-connections. Therefore no "_443.tcp" specifiers.
	// eg: fcpa.sitename.example.org TLSA 2 0 0 <key material>
	genTLSA(FPCAcn, fpcaCert)           // The users can fetch the FPCA-certificate here for validations.
	genTLSA(RootCAcn, caCert)           // And the root ca based upon the FPCA-Issuer-CN.
}

// genTLSA generate a TLSA 2 0 0 record for the given name and certificate
// Make sure to add _443._tcp for certificates uses in TLS-connections. That's what DANE requires.
// But leave them out for Eccentric certificate chains. That allows cn -> DNSSEC chaining.
func genTLSA(name string, cert *x509.Certificate) {
	// choose one of these two methods. The first is the best.
	// t, err := template.New("tlsa").Parse(`{{ define "tlsa" }}{{ .name }}.    IN   TLSA ( 2 0 0 {{ .hex }} ){{ end }}`)
	t, err := template.New("tlsa").Parse(`{{ define "tlsa" }}{{ .name }}.    IN   TYPE52 \# {{ .len }}  ( 020000 {{ .hex }} ){{ end }}`)
	handle(err)
	f, err := os.OpenFile(name + ".bind", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
        handle(err)
	defer f.Close()
	err = t.ExecuteTemplate(f, "tlsa", map[string]interface{}{
		"name": name,
		"hex": fmt.Sprintf("%x", cert.Raw),
		"len": len(cert.Raw) + 3, // +3 for the 2 0 0 characters.
	})
	handle(err)
}

func writePair(serverName string, cert *x509.Certificate, key *rsa.PrivateKey) {
	cBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	kBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})	
	err := writeFile(serverName + ".cert.pem", cBytes, 0444)
	handle(err)
	err = writeFile(serverName + ".key.pem", kBytes, 0400)
	handle(err)
}

// writeFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm;
// It does not overwrite files.
func writeFile(filename string, data []byte, perm os.FileMode) error {
        f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
        if err != nil {
                return err
        }
        n, err := f.Write(data)
        f.Close()
        if err == nil && n < len(data) {
                err = io.ErrShortWrite
        }
        return err
}

// Generate 4k Root CA key.
func generateCA(subjectOrg string, subjectCN string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{subjectOrg},
			CommonName: subjectCN,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: keyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(5, 0, 0).UTC(),

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}

	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

// generate 3k FPCA key.
func generateFPCA(subjectOrg string, subjectCN string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	
	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{subjectOrg},
			CommonName: subjectCN,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: caCert.AuthorityKeyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(5, 0, 0).UTC(),

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

// create plain old https server certificates
// doesn't have to be too strong.
func generateCert(serverName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: serverName,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: caCert.AuthorityKeyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(2, 0, 0).UTC(),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

// Generate a key
func generatePair(serverName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	cert, key, err := generateCert(serverName, caCert, caKey)
		
	if err != nil {
		return tls.Certificate{}, err
			
		}
	return x509Pair(cert, key)
}

func x509Pair(cert *x509.Certificate, key *rsa.PrivateKey) (tls.Certificate, error) {
	cBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	kBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	
	return tls.X509KeyPair(cBytes, kBytes)
}

var (
        maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
        maxBig64       = big.NewInt(maxInt64)
)


func randBigInt() (value *big.Int) {
	value, _ = rand.Int(rand.Reader, maxBig64)
	return
}

func randBytes() (bytes []byte) {
	bytes = make([]byte, 20)
	rand.Read(bytes)
	return
}

func handle(err error) {
	if err != nil {
		panic(err.Error())
	}
}
