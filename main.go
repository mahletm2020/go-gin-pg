package main

import (
	"GO-PG/database"
	"encoding/json"
	"fmt"
	"net/http"
   "github.com/golang-jwt/jwt/v5"
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
	 //use Exec whenever we want to insert update or delete
	//Doing Exec(query) will not use a prepared statement, so lesser TCP calls to the SQL server
		_, err = database.Db.Exec("insert into users(username,password) values ($1,$2)", body.Username, body.Password)
		if err != nil {
			 fmt.Println(err)
			 ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
		} else {
			 ctx.JSON(http.StatusOK, "User is successfully created.")
		}
 
 }
func main() {
		// gin.SetMode(gin.ReleaseMode) //optional to not get warning
		// route.SetTrustedProxies([]string{"192.168.1.2"}) //to trust only a specific value
		route := gin.Default()
		database.ConnectDatabase()
		route.POST("/add", addUser)


	err := route.Run(":8080")
	if err != nil {
		 panic(err)
	}

}
//u stoped at  installing the jwt packae and importing it next time do the password part using bycrypt and then implemen it using this bae doc( Mukesh Murugan)​.
