package main

import "os"

var debugExpired bool
var debugExpiredErr bool

func init() {
	debugExpired = os.Getenv("DEBUG_EXPIRED_CERT") == "1"
	debugExpiredErr = os.Getenv("DEBUG_EXPIRED_CERT_ERR") == "1"
}
