package middleware

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/kwmekyeimonies/go-jwt-auth/config"
	"github.com/kwmekyeimonies/go-jwt-auth/database"
	"github.com/kwmekyeimonies/go-jwt-auth/helper"
	"github.com/kwmekyeimonies/go-jwt-auth/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user := &models.User{
		ID: uuid.New().String(),
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		response := map[string]string{"message": err.Error()}
		helper.ResponseJson(w, http.StatusBadRequest, response)
		return
	}
	defer r.Body.Close()

	//hashPassword
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashPassword)

	//Insert into database
	if err := database.DB.Create(&user).Error; err != nil {
		response := map[string]string{"message": err.Error()}
		helper.ResponseJson(w, http.StatusInternalServerError, response)
		return
	}

	// result := json.NewEncoder(w).Encode(user)
	response := map[string]string{"Message": "Account Succesffuly Created....."}
	helper.ResponseJson(w, http.StatusOK, response)

}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	//Handles request from the Form
	var userInput models.User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		response := map[string]string{"Message": err.Error()}
		helper.ResponseJson(w, http.StatusBadRequest, response)
		return
	}

	defer r.Body.Close()

	var user models.User
	if err := database.DB.Where("username = ?", userInput.Username).First(&user).Error; err != nil {
		switch err {
		case gorm.ErrRecordNotFound:
			response := map[string]string{"Mesage": "Username and password unavailable"}
			helper.ResponseJson(w, http.StatusUnauthorized, response)
			return

		default:
			response := map[string]string{"Message": err.Error()}
			helper.ResponseJson(w, http.StatusUnauthorized, response)
			return
		}

	}

	//Password Checker
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput.Password)); err != nil {
		response := map[string]string{"Message": "Username and password incorrect....."}
		helper.ResponseJson(w, http.StatusUnauthorized, response)
		return
	}

	expTime := time.Now().Add(time.Minute * 1)
	claims := &config.JWTClaim{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "github.com/kwmekyeimonies/go-jwt-auth",
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
	}

	tokenAlgo := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenAlgo.SignedString(config.JWT_KEY)
	if err != nil {
		response := map[string]string{"message": err.Error()}
		helper.ResponseJson(w, http.StatusInternalServerError, response)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    token,
		HttpOnly: true,
	})

	response := map[string]string{"Message": "Login Succesfull...."}
	helper.ResponseJson(w, http.StatusOK, response)

}

func Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	response := map[string]string{"Message": "Logout succesfull....."}
	helper.ResponseJson(w, http.StatusOK, response)

}
