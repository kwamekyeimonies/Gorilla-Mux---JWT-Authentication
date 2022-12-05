package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/kwmekyeimonies/go-jwt-auth/database"
	"github.com/kwmekyeimonies/go-jwt-auth/router"
)

//

func main() {
	r := router.Router()
	port := ":8090"

	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	database.Connect_Database()

	fmt.Println("Server running on port ", port)
	log.Fatal(http.ListenAndServe(port, r))
}
