package cmdgone

import (
	"fmt"
	"os"
)

func Main() {
	fmt.Println("This binary has been deprecated and will be removed entirely in the future.")
	os.Exit(1)
}
