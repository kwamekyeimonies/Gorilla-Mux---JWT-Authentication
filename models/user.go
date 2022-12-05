package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	ID       string `json:"id" gorm:"primaryKey"`
	FullName string `json:"fullname" gorm:"unique"`
	Username string `json:"username" gorm:"varchar(300)"`
	Password string `json:"password" gorm:"varcahr(300)"`
}
