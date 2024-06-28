package main

import (
	"identity/src"
	"log"
)

func main() {
	iamIdentity, done := identity.GetIam()
	if done {
		return
	}

	log.Print(iamIdentity)
}
