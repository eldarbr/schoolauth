package main

import (
	"context"
	"log"

	"github.com/eldarbr/schoolauth"
)

func main() {
	_, err := schoolauth.Auth(context.Background(), "neutraea", "carleeme")
	if err != nil {
		log.Println(err)
	}
}
