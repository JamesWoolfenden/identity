package main

import (
	Identity "identity/src"
	"log"
)

func main() {
	iamIdentity, err := Identity.GetIam()
	if err != nil {
		return
	}

	log.Print(iamIdentity)
}
