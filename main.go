//go:build !test

package main

import (
	"context"

	Identity "github.com/jameswoolfenden/identity/src"
	"github.com/rs/zerolog/log"
)

func main() {
	iamIdentity, err := Identity.GetIam(context.Background())
	if err != nil {
		return
	}

	log.Info().Msgf("Identity %s", iamIdentity)
}
