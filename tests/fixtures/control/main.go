package main

import (
	"fmt"
	"os"

	"github.com/JustIkra/umir-gateway/tests/fixtures/protocol"
)

func main() {
	var call func() error
	if len(os.Args) == 2 && os.Args[1] == "request" {
		call = protocol.RequestFromStdin
	} else if len(os.Args) == 4 && os.Args[1] == "profile" && os.Args[2] == "--request" && os.Args[3] == protocol.ProfileRequestPath {
		call = protocol.CatalogFromFile
	}
	if call == nil {
		os.Exit(1)
	}
	if err := call(); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, "fixture control failed"); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}
