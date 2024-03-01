package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"io/ioutil"
	"time"

	"github.com/gin-gonic/gin"

	"litegix-agent/auth"
	handlers "litegix-agent/handler"
	//"litegix-agent/middleware"
)

func init() {

}

func loadConfiguration(file string) handlers.Config {
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		log.Println(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)

	config := handlers.Config{}
	err = jsonParser.Decode(&config)
	if err != nil {
		log.Fatal("can't decode config JSON: ", err)
	}
	return config
}

func test_nginx() {
	sites_enabled := "/"
	files, err := ioutil.ReadDir(sites_enabled)
  if err == nil {
	  for _, f := range files {
		  log.Println(sites_enabled + f.Name())
	  }
	}
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	config := loadConfiguration("/litegix/litegix-agent/config.json")
	log.Println(config.ServerID)

	//test_nginx()

	var rd = auth.NewAuth()
	var tk = auth.NewToken()
	var service = handlers.NewHandler(rd, tk, config)

	var router = gin.Default()

	router.POST("/login", service.Login)
	router.POST("/logout", /*middleware.TokenAuthMiddleware(),*/ service.Logout)
	router.POST("/refresh", service.Refresh)

	router.POST("/system/user", /*middleware.TokenAuthMiddleware(),*/ service.CreateSystemUser)
	router.DELETE("/system/user/:name", /*middleware.TokenAuthMiddleware(),*/ service.DeleteSystemUser)
	router.PUT("/system/user/:name/changepwd", /*middleware.TokenAuthMiddleware(),*/ service.ChangeSystemUserPassword)

	router.POST("/database", /*middleware.TokenAuthMiddleware(),*/ service.CreateDatabase)
	router.DELETE("/database/:name", /*middleware.TokenAuthMiddleware(),*/ service.DeleteDatabase)

	router.POST("/database/user", /*middleware.TokenAuthMiddleware(),*/ service.CreateDatabaseUser)
	router.DELETE("/database/user/:name", /*middleware.TokenAuthMiddleware(),*/ service.DeleteDatabaseUser)

	router.POST("/php/version", /*middleware.TokenAuthMiddleware(),*/ service.ChangePhpVersion)
	router.POST("/sshkey", /*middleware.TokenAuthMiddleware(),*/ service.AddSSHKey)
	router.POST("/deploymentkey", /*middleware.TokenAuthMiddleware(),*/ service.AddDeploymentKey)
	router.POST("/cronjob", /*middleware.TokenAuthMiddleware(),*/ service.CreateCronJob)
	router.POST("/supervisorjob/create", /*middleware.TokenAuthMiddleware(),*/ service.CreateSuperVisor)
	router.POST("/firewall/addrule", /*middleware.TokenAuthMiddleware(),*/ service.AddFirewallRule)
	router.GET("/services", /*middleware.TokenAuthMiddleware(),*/ service.ViewServices)

	router.POST("/webapps/wordpress", /*middleware.TokenAuthMiddleware(),*/ service.InstallWordpress)
	router.POST("/webapps/ssl", /*middleware.TokenAuthMiddleware(),*/ service.InstallSSL)

	srv := &http.Server{
		Addr:    ":21000",
		Handler: router,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	//Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("Server exiting")
}
