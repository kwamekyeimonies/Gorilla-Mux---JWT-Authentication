package router

import (
	"github.com/gorilla/mux"
	"github.com/kwmekyeimonies/go-jwt-auth/middleware"
)

func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/register", middleware.Register).Methods("POST")
	router.HandleFunc("/login", middleware.Login).Methods("POST")
	router.HandleFunc("/", middleware.Logout).Methods("GET")

	return router
}
