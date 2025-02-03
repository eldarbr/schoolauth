package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/eldarbr/schoolauth"
)

func main() {
	flgUsername := flag.String("u", "", "username")
	flgPassword := flag.String("p", "", "password")

	flag.Parse()

	if *flgUsername == "" || *flgPassword == "" {
		fmt.Println("Error - please provide username and password")

		return
	}

	_, err := schoolauth.Auth(context.Background(), *flgUsername, *flgPassword)
	if err != nil {
		fmt.Println("Error -", err)

		return
	}

	fmt.Println("Auth complete")
}
