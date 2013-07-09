// Eccentric Authentication Blog site
//
// Create a blog site that allows bloggers to establish a reputation (good or bad) based upon what they write.
// Note, everything anyone writes is signed by their private key.
// Unless one writes as Anonymous Coward.

// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

package main

import (
	"log"
	"net/http"
//	"net/url"
	"os"
	"crypto/tls"
	"html/template"
	"flag"
	"regexp"

	"github.com/gwitmond/eccentric-authentication" // package eccentric

	// These are for the data storage
	"github.com/coopernurse/gorp"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// The things to set before running.
var certDir = flag.String("config", "cert", 
	"Directory where the certificates and keys are found.") 

var fpcaCert = flag.String("fpcaCert", "blogFPCA.cert.pem", 
	"File with the Certificate of the First Party Certificate Authority that we accept for our clients.")

var fpcaURL = flag.String("fpcaURL", "https://register-blog.wtmnd.nl", 
	"URL of the First Party Certificate Authority where clients can get their certificate.")

var hostname = flag.String("hostname", "blog.wtmnd..nl", 
	"Hostname of the application. Determines which cert.pem and key.pem are used for the TLS-connection.")

var bindAddress = flag.String("bind", "[::]:10446", 
	"Address and port number where to bind the listening socket.") 

// global state
var ecca = eccentric.Authentication{}
 
var templates = template.Must(template.ParseFiles(
	"templates/homepage.template",
	"templates/showBlogs.template",
	"templates/showBlog.template",
	"templates/createBlog.template",

// standard templates
	"templates/needToRegister.template",
	"templates/menu.template",
	"templates/tracking.template")) 


func init() {
	http.HandleFunc("/", homePage)

	http.HandleFunc("/blogs", showBlogs) // show list of blogs
	http.Handle("/createblog", ecca.LoggedInHandler(createBlog, "needToRegister.template"))
	http.HandleFunc("/blog/", showBlog) // show a single blog/<id>  (for everyone)

	//http.Handle("/read-messages", ecca.LoggedInHandler(readMessages, "needToRegister.template"))
	//http.Handle("/send-message", ecca.LoggedInHandler(sendMessage, "needToRegister.template"))

	http.Handle("/static/", http.FileServer(http.Dir(".")))
}


func main() {
	flag.Parse()
	ecca = eccentric.Authentication{
		RegisterURL:  *fpcaURL, // "https://register-cryptoblog.wtmnd.nl:10501/register-pubkey",
		Templates: templates,   //Just copy the templates variable
		Debug: true,  // show debugging
	}

	// This CA-pool specifies which client certificates can log in to our site.
	pool := eccentric.ReadCert( *certDir + "/" + *fpcaCert) // "datingLocalCA.cert.pem"
	
	log.Printf("Started at %s. Go to https://%s/ + port", *bindAddress, *hostname)
	
	server := &http.Server{Addr: *bindAddress,
		TLSConfig: &tls.Config{
			ClientCAs: pool,
			ClientAuth: tls.VerifyClientCertIfGiven},
	}
	// Set  the server certificate to encrypt the connection with TLS
	ssl_certificate := *certDir + "/" + *hostname + ".cert.pem"
	ssl_cert_key   := *certDir + "/" + *hostname + ".key.pem"
	
	check(server.ListenAndServeTLS(ssl_certificate, ssl_cert_key))
}


func homePage(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/" {
		check(templates.ExecuteTemplate(w, "homepage.template",  nil))
		return;
	}
	http.NotFound(w, req)
}


// Show blogs, no authentication required
func showBlogs (w http.ResponseWriter, req *http.Request) {
 	check(templates.ExecuteTemplate(w, "showBlogs.template", map[string]interface{}{
 		"blogs": getBlogs() }))
}

// match ../blog/<id>(/rest)?
var blogRE = regexp.MustCompile(`^/blog/([\d]+)/?`)

// showBlog shows a single blow with comments
func showBlog(w http.ResponseWriter, req *http.Request) {
	blogId := getFirst(blogRE.FindStringSubmatch(req.URL.Path))
	blog := getBlog(blogId)
	if blog == nil {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Eccentric-Authentication", "verify")
	w.Header().Set("Content-Type", "text/html, charset=utf8")
 	check(templates.ExecuteTemplate(w, "showBlog.template", blog))
}

// createBlog lets the user creata a blog
func createBlog(w http.ResponseWriter, req *http.Request) {
 	// LoggedInHander made sure our user is logged in with a correct certificate
 	cn := req.TLS.PeerCertificates[0].Subject.CommonName
 	switch req.Method {
 	case "GET": 
 		check(templates.ExecuteTemplate(w, "createBlog.template", map[string]interface{}{
 			"CN": cn,
 		}))

 	case "POST":
 		req.ParseForm()
		err := saveBlog(Blog{
			Blogger: cn,
			Title: req.Form.Get("title"),
			Text: req.Form.Get("cleartext"),
			Signature: req.Form.Get("signature"),
		})
		check(err)	 
		//TODO: make a nice template with a menu and a redirect-link.
 		w.Write([]byte(`<html><p>Thank you for your entry. <a href="/blogs">Show all blogs.</a></p></html>`))

 	default: 
 		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
 	}
 }


// // editProfile lets the user fill in his/her profile data to lure the aliens into the hive.
// func editProfile(w http.ResponseWriter, req *http.Request) {
// 	// LoggedInHander made sure our user is logged in with a correct certificate
// 	cn := req.TLS.PeerCertificates[0].Subject.CommonName
// 	switch req.Method {
// 	case "GET": 
// 		alien := getAlien(cn)  // alien or nil
// 		check(templates.ExecuteTemplate(w, "editProfile.template", map[string]interface{}{
// 			"CN": cn,
// 			"alien": alien,
// 			"races": races,
// 			"occupations": occupations,
// 		}))

// 	case "POST":
// 		req.ParseForm()
// 		saveAlien(Alien{
// 			CN: cn,
// 			Race: req.Form.Get("race"),
// 			Occupation: req.Form.Get("occupation"),
// 		})
// 		//TODO: make a nice template with a menu and a redirect-link.
// 		w.Write([]byte(`<html><p>Thank you for your entry. <a href="/aliens">Show all aliens.</a></p></html>`))

// 	default: 
// 		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
// 	}
// }


// // Checked sets the checked attribute.
// // To be called from within templates.
// func (alien *Alien) Checked(data string) string {
//  	if alien == nil { return "" } // no data, nothing selected
//  	if alien.Race == data { return "checked"} // if the data is in the Alien.Race -> true
//  	if alien.Occupation == data { return "checked" } // or if the data is in the Occup. -> true
//  	return ""
// }


// // readMessages shows you the messages other aliens have sent you.
// func readMessages (w http.ResponseWriter, req *http.Request) {
// 	// User is logged in
// 	cn := req.TLS.PeerCertificates[0].Subject.CommonName
// 	switch req.Method {
// 	case "GET": 
// 		// set this header to signal the user's Agent to perform data decryption.
// 		w.Header().Set("Eccentric-Authentication", "decryption=\"required\"")
// 		w.Header().Set("Content-Type", "text/html, charset=utf8")
// 		messages := getMessages(cn)
// 		check(templates.ExecuteTemplate(w, "readMessage.template", map[string]interface{}{
// 			"CN": cn,
// 			"messages": messages,
// 		}))
		
// 	default:
//  		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )

// 	}
// }


// // sendMessage takes an encrypted message and delivers it at the message box of the recipient
// // Right now, that's our own dating site. It could perform a MitM.
// // See: http://eccentric-authentication.org/eccentric-authentication/private_messaging.html
// func sendMessage(w http.ResponseWriter, req *http.Request) {
// 	cn := req.TLS.PeerCertificates[0].Subject.CommonName
// 	switch req.Method {
// 	case "GET": 
// 		req.ParseForm()
// 		toCN := req.Form.Get("addressee")

// 		// idURL 
// 		// We do provide a path to the CA to let the user retrieve the public key of the recipient.
// 		// User is free to obtain in other ways... :-)
// 		idURL, err := url.Parse(*fpcaURL)
// 		idURL.Path = "/get-certificate"
// 		check(err)
// 		q := idURL.Query()
// 		q.Set("nickname", toCN)
// 		toURL.RawQuery = q.Encode()

//  		check(templates.ExecuteTemplate(w, "sendMessage.template", map[string]interface{}{
// 			"CN": cn,            // from us
// 			"ToCN": toCN,   // to recipient
// 			"IdURL": idURL, // where to find the certificate with public key
// 		}))

// 	case "POST":
// 		req.ParseForm()
// 		ciphertext := req.Form.Get("ciphertext")
// 		if ciphertext == "" {
// 			w.Write([]byte(`<html><p>Your message was not encrypted. We won't accept it. Please use the ecca-proxy.</p></html>`))
// 			return
// 		}
// 		saveMessage(Message{
// 			FromCN: cn,
// 			ToCN: req.Form.Get("addressee"),
// 			Ciphertext: ciphertext,
// 		})
// 		w.Write([]byte(`<html><p>Thank you, your message will be delivered at galactic speed.</p></html>`))

// 	default:
//  		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
// 	}

// }



	
func check(err error) {
	if err != nil {
		panic(err)
	}
}



// Marshalling

// Blogger struct contains data about the blogger (the person writing blogs or comments)
type Blogger struct {
	Blogger []byte   // the CN of the bloggers' certificate
}

// Blog struct contains the blog entries
type Blog struct {
	Id          int        // auto increment id
	Blogger string  // the CN of the bloggers' certificate
	Date     string
	Title      string
	Text      string
	Signature string // with openssl signing, it's best a string, with x509, it would be []byte...
}


var dbmap *gorp.DbMap

func init() {
	db, err := sql.Open("sqlite3", "./cryptoblog.sqlite3")
	check(err)
	dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	dbmap.AddTableWithName(Blog{}, "blogs").SetKeys(true, "Id")
	dbmap.AddTableWithName(Blogger{}, "bloggers").SetKeys(false, "Blogger")

	dbmap.CreateTables() // if not exists
	
	dbmap.TraceOn("[gorp]", log.New(os.Stdout, "myapp:", log.Lmicroseconds)) 
}

func getBlogs() (blogs []*Blog) {
	_, err := dbmap.Select(&blogs, "SELECT * FROM blogs")
	check(err)
	return // blogs
}

func saveBlog(blog Blog) error {
	return dbmap.Insert(&blog)
}

// return a blog or a nil.. TODO.. test it, check it.
func getBlog(blogid string) (blog *Blog) {
	res, err := dbmap.Get(blog, blogid)
	log.Printf("Blog is %#v, err is %#v\n", res, err)
	check(err)
	if res == nil { return nil } //type  assert can't handle nil :-(
	return res.(*Blog) // whatever we got, either a blog or a nil ( we hope) Todo: find out if that's true.
}

// Return the certificates but don't convert to x509.Certificate
// structures, just output the strings. Caller needs to do the hard
// work. Don't make it easy to DoS us.
// args is site, cn, [certificate]
// func get_certificates(args... interface{}) ([]*DBCert, error) {
// 	var query string
// 	switch {
// 	case len(args) == 2:
// 		query = "SELECT * from certificates WHERE realm = ? AND username = ?"
		
// 	case len(args) == 3:
// 		query = "SELECT * from certificates WHERE realm = ? AND username = ? AND certificate = ?"
// 	}
 
// 	certs, err := dbmap.Select(DBCert{}, query, args...)
// 	if err != nil { return nil, err }
	
// 	// certificates := make([]x509.Certificate, len(certs))
// 	log.Printf("Certs are: %#v\n", certs)
// 	var res = make([]*DBCert, len(certs))
// 	for i, dbcert := range certs {
// 		res[i] = dbcert.(*DBCert) // bloody typecast...
// 		// Is this the right way to do this in Go?
// 	}
// 	return res, nil
// }


// Return the first (not zeroth) string in the array, if not nil (usefull for regexps)
func getFirst(s []string) string {
        if s != nil {
                return s[1]
        }
        return ""       
}
