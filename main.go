package main

import (
	"github.com/jameswoolfenden/identity/src"
	"log"
)

func main() {
	iamIdentity, err := Identity.GetIam()
	if err != nil {
		return
	}

	log.Print(iamIdentity)
}
