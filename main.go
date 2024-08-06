package main

import "log"

const (
	GlobalVersion string = `v1.0.0`
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

func main() {
}
