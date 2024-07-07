package main

import (
	"GO-PG/database"
	"GO-PG/auth"
	"encoding/json"
	"fmt"
	"net/http"
	"golang.org/x/crypto/bcrypt"
	"github.com/gin-gonic/gin"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

	// Generate a bcrypt hash from the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(500, "Error hashing password")
		return
	}
	fmt.Println("Received Username:", body.Username)
	fmt.Println("Received Password:", body.Password)
	// Store the hashed password in the database
	_, err = database.Db.Exec("insert into users(username,password) values ($1,$2)", body.Username, string(hashedPassword))

	if err != nil {
		fmt.Println(err)
		ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
	} else {
		ctx.JSON(http.StatusOK, "User is successfully created.")
	}
}

func loginUser(ctx *gin.Context) {
	body := User{}
	err := ctx.BindJSON(&body)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, "Invalid request")
		return
	}

	var storedUser User
	err = database.Db.QueryRow("SELECT username, password FROM users WHERE username=$1", body.Username).Scan(&storedUser.Username, &storedUser.Password)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid username or password")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(body.Password))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid username or password")
		return
	}

	token, err := auth.GenerateJWT(storedUser.Username)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, "Error generating token")
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Authorization header missing")
			return
		}

		tokenString := authHeader[len("Bearer "):]
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx.Set("username", claims.Username)
		ctx.Next()
	}
}

func main() {
	database.ConnectDatabase()
	router := gin.Default()

	router.POST("/users", addUser)
	router.POST("/login", loginUser)

	protected := router.Group("/protected")
	protected.Use(AuthMiddleware())
	{
		protected.GET("/data", func(ctx *gin.Context) {
			username := ctx.GetString("username")
			ctx.JSON(http.StatusOK, gin.H{"message": "Hello " + username})
		})
	}

	router.Run("localhost:8080")
}
