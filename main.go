package main

import (
	"identity/src"
	"log"
)

func main() {
	iamIdentity, err := identity.GetIam()
	if err != nil {
		return
	}

	log.Print(iamIdentity)
}
