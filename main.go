//go:build !test
// +build !test

package main

import (
	Identity "github.com/jameswoolfenden/identity/src"
	"github.com/rs/zerolog/log"
)

func main() {
	iamIdentity, err := Identity.GetIam()
	if err != nil {
		return
	}

	log.Info().Msgf("Identity %s", iamIdentity)
}
