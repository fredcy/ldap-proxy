package ldapproxy

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
)

type Person struct {
	Dn        string
	Uid       []string
	FirstName string
	LastName  string
	OrgStatus string
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

		for _, entry := range sr.Entries {
			//entry.Print()
			person := Person{}
			person.Dn = entry.DN
			person.FirstName = entry.GetAttributeValue("givenName")
			person.LastName = entry.GetAttributeValue("sn")
			person.OrgStatus = entry.GetAttributeValue("organizationalStatus")
			person.Uid = entry.GetAttributeValues("uid")
			persons <- person
		}
	}()

	return persons, nil
}
