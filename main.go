package main

import (
	"GO-PG/database"
	"encoding/json"
	"fmt"
	"net/http"
   //"log"
	// "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"github.com/gin-gonic/gin"
)
type User struct {
	Username string
	Password string
 }
 func addUser(ctx *gin.Context) {
	body := User{}
	data, err := ctx.GetRawData()
	if err != nil {
		ctx.AbortWithStatusJSON(400, "User is not defined")
		return
	}
	err = json.Unmarshal(data, &body)
	if err != nil {
		ctx.AbortWithStatusJSON(400, "Bad Input")
		return
	}

	//  Generate a bcrypt hash from the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(500, "Error hashing password")
		return
	}
	fmt.Println("Received Username:", body.Username)
	fmt.Println("Received Password:", body.Password)
	//  Store the hashed password in the database
	_, err = database.Db.Exec("insert into users(username,password) values ($1,$2)", body.Username, string(hashedPassword))

	if err != nil {
		fmt.Println(err)
		ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
	} else {
		ctx.JSON(http.StatusOK, "User is successfully created.")
	}
}


func main() {
	database.ConnectDatabase()
	router := gin.Default()
	router.POST("/users", addUser)
	router.Run("localhost:8080")
}
