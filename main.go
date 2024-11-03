//go:build !test
// +build !test

package main

import (
	"log"

	Identity "github.com/jameswoolfenden/identity/src"
)

func main() {
	iamIdentity, err := Identity.GetIam()
	if err != nil {
		return
	}

	log.Print(iamIdentity)
}
