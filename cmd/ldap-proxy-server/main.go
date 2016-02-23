package main

import (
	"encoding/json"
	"flag"
	"fmt"
	ldapproxy "github.com/fredcy/ldap-proxy"
	"log"
	"net/http"
	"os"
	"time"
)

const searchprefix = "/search/"

func searchHandler(w http.ResponseWriter, r *http.Request, ldapAddress string) {
	pattern := r.URL.Path[len(searchprefix):]

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

	http.HandleFunc(searchprefix, wrapLog(wrapLDAP(searchHandler, ldapAddress)))
	log.Printf("ldap-proxy listening at %v", *address)
	log.Fatal(http.ListenAndServe(*address, nil))
}
