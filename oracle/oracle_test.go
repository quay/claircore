package oracle

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestMain(m *testing.M) {
	log.Logger = zerolog.Nop()
	os.Exit(m.Run())
}
