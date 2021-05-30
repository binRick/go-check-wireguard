package main

import (
	"golang.org/x/net/dns/dnsmessage"
)

func mustNewName(name string) dnsmessage.Name {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	return n
}

func msg_demo() []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName("google.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	//pp.Print(msg)

	buf, err := msg.Pack()
	Fatal(err)
	return buf
}
