package ldapproxy

/* See https://godoc.org/github.com/go-ldap/ldap */

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"log"
	"strings"
)

type Person struct {
	Dn        string
	Uid       []string
	FirstName string
	LastName  string
	OrgStatus string
	Ous       []string
}

func Search(ldapAddress, pattern string) (chan Person, error) {
	persons := make(chan Person)

	conn, err := ldap.Dial("tcp", ldapAddress)
	if err != nil {
		return persons, err
	}
	defer conn.Close()

	err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return persons, err
	}

	filter := fmt.Sprintf("(|(uid=*%s*)(cn=*%s*))", pattern, pattern)

	attributes := ([]string{"dn", "sn", "givenName", "organizationalStatus", "uid"})

	searchRequest := ldap.NewSearchRequest(
		"ou=People,dc=imsa,dc=edu",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return persons, err
	}

	go func() {
		defer close(persons)

	entries:
		for _, entry := range sr.Entries {
			//entry.Print()

			ous := ousFromDn(entry.DN)
			for _, ou := range ous {
				ou = strings.ToLower(ou)
				if ou == "faxes" || ou == "machines" {
					// ignore entries in these OUs
					continue entries
				}

				if strings.HasPrefix(ou, "classof") {
					continue entries
				}
			}

			person := Person{}
			person.Dn = entry.DN

			// Save only one value for most attributes since that's all we store.
			person.FirstName = entry.GetAttributeValue("givenName")
			person.LastName = entry.GetAttributeValue("sn")
			person.OrgStatus = entry.GetAttributeValue("organizationalStatus")

			// We do use multiple uid values for uid (for alumni).
			person.Uid = entry.GetAttributeValues("uid")

			person.Ous = ous

			persons <- person
		}
	}()

	return persons, nil
}

// ousFromDn does crude parsing on a DN value and returns the 'ou' values other
// than "People".  E.g. for "uid=kzine,ou=Students,ou=People,dc=imsa,dc=edu" it
// returns just ["Students"].
func ousFromDn(dn string) []string {
	parts := strings.Split(dn, ",")
	var ous = []string{}
	for _, part := range parts {
		nameVal := strings.Split(part, "=")
		if len(nameVal) != 2 {
			log.Printf("error: bad DN part: %v", part)
			continue
		}
		if nameVal[0] == "ou" {
			if nameVal[1] != "People" {
				ous = append(ous, nameVal[1])
			}
		}
	}
	return ous
}
