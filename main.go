/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>

*/
package main

import (
	"github.com/getcrasec/crasec/cmd"
	_ "modernc.org/sqlite" // registers the SQLite driver required by syft's RPM cataloger
)

func main() {
	cmd.Execute()
}
