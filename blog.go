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
	"crypto/tls"
	"html/template"
	"flag"
	"regexp"
	"strconv"
	"fmt"
	"github.com/gwitmond/eccentric-authentication" // package eccentric
)


// Blog struct contains the blog entries
type Blog struct {
	Id          int        // auto increment id
	Blogger string  // the CN of the bloggers' certificate
	Date     string
	Title      string
	Text      string
	Signature string // with openssl signing, it's best a string, with x509, it would be []byte...
}

// Comment struct contains the comment entries
type Comment struct {
	Id          int        // auto increment id
	BlogId  int     // the blog that it's a comment to.
	Blogger string  // the CN of the bloggers' certificate
	Date     string
	Title      string
	Text      string
	Signature string // with openssl signing, it's best a string, with x509, it would be []byte...
}

// global state
var ds *Datastore
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


func initServeMux(mux *http.ServeMux) *http.ServeMux {
	mux.HandleFunc("/", homePage)

	mux.HandleFunc("/blogs", showBlogs) // show list of blogs
	mux.Handle("/createblog", ecca.LoggedInHandler(createBlog, "needToRegister.template"))
	mux.HandleFunc("/blog/", showBlog) // show a single blog/<id>  (for everyone)

	mux.HandleFunc("/submit-comment", submitComment)   // (optionally signed)

	//mux.Handle("/read-messages", ecca.LoggedInHandler(readMessages, "needToRegister.template"))
	//mux.Handle("/send-message", ecca.LoggedInHandler(sendMessage, "needToRegister.template"))

	mux.Handle("/static/", http.FileServer(http.Dir(".")))
	return mux
}

type BlogHandler struct {
	mux *http.ServeMux
}

func (bh *BlogHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	bh.mux.ServeHTTP(w, req)
}

func main() {
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

	flag.Parse()

	ecca = eccentric.Authentication{
		RegisterURL:  *fpcaURL, // "https://register-cryptoblog.wtmnd.nl:10501/register-pubkey",
		Templates: templates,   //Just copy the templates variable
		Debug: true,  // show debugging
	}

	// This CA-pool specifies which client certificates can log in to our site.
	pool := eccentric.ReadCert( *certDir + "/" + *fpcaCert) // "datingLocalCA.cert.pem"
	ds = DatastoreOpen("cryptoblog.sqlite3")
	log.Printf("Started at %s. Go to https://%s/ + port", *bindAddress, *hostname)

	bloghandler := &BlogHandler{
		mux: initServeMux(http.NewServeMux()),
	}

	server := &http.Server{
		Addr: *bindAddress,
		Handler: bloghandler,
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
 		"blogs": ds.getBlogs() }))
}

// match ../blog/<id>(/rest)?
var blogRE = regexp.MustCompile(`^/blog/([\d]+)/?`)

// showBlog shows a single blow with comments
func showBlog(w http.ResponseWriter, req *http.Request) {
	blogId := getFirst(blogRE.FindStringSubmatch(req.URL.Path))
	blog := ds.getBlogStr(blogId)
	if blog == nil {
		http.NotFound(w, req)
		return
	}
	comments := ds.getComments(blog.Id)
	w.Header().Set("Eccentric-Authentication", "verify")
	w.Header().Set("Content-Type", "text/html, charset=utf8")
 	check(templates.ExecuteTemplate(w, "showBlog.template", map[string]interface{}{
		"Blog": blog,
		"Comments": comments}))
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
		// TODO: Verify signature before storing.
		blog := &Blog{
			Blogger: cn,
			Title: req.Form.Get("title"),
			Text: req.Form.Get("cleartext"),
			Signature: req.Form.Get("signature"),
		}
		ds.writeBlog(blog) // sets blog.Id
		http.Redirect(w, req, fmt.Sprintf("/blog/%v", blog.Id), http.StatusTemporaryRedirect  )

 	default: 
 		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
 	}
}

// submitComment lets the user add a comment
// it can be signed or unsigned
func submitComment(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
 	case "POST":
 		req.ParseForm()
		// check if our user is logged in with a correct certificate
		// otherwise, we call him "anonymous"
		cn, _ := checkUserIsLoggedIn(req)
		blogId, err := strconv.Atoi(req.Form.Get("blogId"))
		check(err)
		// TODO: Verify signature before storing.
		comment := &Comment{
			BlogId: blogId,
			Blogger: cn,
			Title: req.Form.Get("title"),
			Text: req.Form.Get("cleartext"),
			Signature: req.Form.Get("signature"),
		}
		ds.writeComment(comment) // sets comment.Id
		http.Redirect(w, req, fmt.Sprintf("/blog/%v#%v", blogId, comment.Id), http.StatusTemporaryRedirect)

 	default: 
 		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
 	}
}

// breaks if there is an error
func checkUserIsLoggedIn(req *http.Request) (string, bool) {
	if len(req.TLS.PeerCertificates) == 0 {
		return "anonymous", false
	}
	return req.TLS.PeerCertificates[0].Subject.CommonName, true
}


	
func check(err error) {
	if err != nil {
		panic(err)
	}
}




// Return the first (not zeroth) string in the array, if not nil (usefull for regexps)
func getFirst(s []string) string {
        if s != nil {
                return s[1]
        }
        return ""       
}
