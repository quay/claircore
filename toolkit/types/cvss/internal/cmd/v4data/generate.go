package main

//go:generate go tool mkragel parser.rl

// Need the reverse lookup table for the fragment parser.
//go:generate go tool revlookup -package main -version 4 -o revlookup.go
