package main

import (
    "crypto/md5"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
)

func Fingerprint(b []byte) [16]byte { return md5.Sum(b) }

func Keys() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

var insecure = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
