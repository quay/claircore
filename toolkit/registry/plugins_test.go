package registry

import (
	"context"
	"fmt"
	"reflect"
)

type MyPlugin interface {
	Example()
}

func Example() {
	// MyPlugin is an exported interface type.
	desc := Description[MyPlugin]{
		ConfigSchema: `{}`,
		New: func(_ context.Context, _ func(_ any) error) (MyPlugin, error) {
			return nil, nil
		},
	}
	err := Register[MyPlugin](`urn:claircore:registry:myplugin:example`, &desc)
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println("OK")
	}
	for _, n := range All[MyPlugin]() {
		fmt.Println("all:", n)
	}
	for _, n := range Default[MyPlugin]() {
		fmt.Println("default:", n)
	}
	// Output:
	// OK
	// all: urn:claircore:registry:myplugin:example
}

func Example_failure() {
	// MyPlugin is an exported interface type.
	desc := Description[MyPlugin]{
		ConfigSchema: `{}`,
		New: func(_ context.Context, _ func(_ any) error) (MyPlugin, error) {
			return nil, nil
		},
	}
	var err error
	err = Register[MyPlugin](`urn:claircore:wrongpackage:myplugin:example`, &desc)
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println("OK")
	}
	err = Register[MyPlugin](`urn:claircore:registry:wrongname:example`, &desc)
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println("OK")
	}

	// Output:
	// error: registry: bad name "urn:claircore:wrongpackage:myplugin:example": expected "registry" for system component, got "wrongpackage"
	// error: registry: bad name "urn:claircore:registry:wrongname:example": expected "myplugin" for kind component, got "wrongname"
}

// Reset is a test-only method to reset the global registry.
//
// Be wary of concurrency issues.
func Reset() {
	registry.Lock()
	defer registry.Unlock()
	registry.Lookup = make(map[reflect.Type]any)
}
