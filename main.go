/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>

*/
package main

import (
	"github.com/getcrasec/crasec/cmd"

	// Registers the "sqlite" database/sql driver required by syft's RPM
	// cataloger. Grype's vulnerability DB layer (grype/db/internal/gormadapter)
	// pulls in github.com/glebarez/go-sqlite, which registers the same driver
	// name; importing modernc.org/sqlite directly here as well would panic at
	// init with "Register called twice for driver sqlite", so rely on Grype's
	// transitive import instead of adding our own.
	_ "github.com/glebarez/go-sqlite"
)

func main() {
	cmd.Execute()
}
