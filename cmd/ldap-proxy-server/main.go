package main

import (
	"encoding/json"
	"flag"
	"fmt"
	ldapproxy "github.com/fredcy/ldap-proxy"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"time"
)

const searchprefix = "/search/"

func searchHandler(w http.ResponseWriter, r *http.Request, ldapAddress string) {
	vars := mux.Vars(r)
	pattern := vars["query"]

	persons, err := ldapproxy.Search(ldapAddress, pattern)
	if err != nil {
		log.Print(err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)

	fmt.Fprint(w, "[")

	first := true
	for person := range persons {
		if !first {
			fmt.Fprint(w, ",")
		}
		if err := enc.Encode(&person); err != nil {
			log.Println(err)
			return
		}
		first = false
	}
	fmt.Fprintln(w, "]")
}

func wrapCORS(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fn(w, r)
	}
}

func wrapLDAP(fn func(http.ResponseWriter, *http.Request, string), address string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, address)
	}
}

func wrapLog(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		fn(w, r)
		endTime := time.Now()
		log.Printf("served %v to %v in %v",
			r.URL, r.RemoteAddr, endTime.Sub(startTime))
	}
}

func main() {
	address := flag.String("address", ":8082", "Listen and serve at this address")
	flag.Parse()

	ldapAddress := os.Getenv("LDAP_ADDRESS")
	if ldapAddress == "" {
		log.Fatal("LDAP_ADDRESS is not set in env")
	}

	r := mux.NewRouter()

	r.HandleFunc("/search/{query}", wrapLog(wrapLDAP(searchHandler, ldapAddress)))
	http.Handle("/", &MyServer{r})

	log.Printf("ldap-proxy listening at %v", *address)
	log.Fatal(http.ListenAndServe(*address, nil))
}

/* See http://stackoverflow.com/questions/12830095/setting-http-headers-in-golang about CORS */

type MyServer struct {
	r *mux.Router
}

func (s *MyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		rw.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	}
	// Stop here if its Preflighted OPTIONS request
	if req.Method == "OPTIONS" {
		return
	}
	// Lets Gorilla work
	s.r.ServeHTTP(rw, req)
}
