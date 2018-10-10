package main

import "flag"

// These flags represent all the available command line flags
var (
	itagFlag      = flag.String("instance-tag", "", "The instance tag (a 4-byte big endian number written in hex) to use for validating data")
	publicKeyFlag = flag.String("public-key", "", "The public key (written in hex) to use for validating data")
)
