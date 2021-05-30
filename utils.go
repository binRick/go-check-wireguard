package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
)

func get_hash(in string) string {
	hash := md5.Sum([]byte(fmt.Sprintf(`%s`, in)))
	h := hex.EncodeToString(hash[:])[0:16]
	return h
}

func ipChecksum(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

func Fatal(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
