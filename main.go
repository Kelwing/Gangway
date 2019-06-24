package main

import (
	"crypto/rsa"
	"fmt"
	"html/template"
	"io"
	"os"

	"github.com/gorilla/sessions"
	"github.com/kelwing/Gangway/cfg"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

type AuthFramework struct {
	*echo.Echo
	config  cfg.Config
	KeyPair *rsa.PrivateKey
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	cf, err := os.Open("config/config.yaml")
	if err != nil {
		config := cfg.NewConfig()
		err := config.GenerateSample()
		if err == nil {
			log.Fatal("Generated sample config")
		}
	}

	fi, err := os.Stat("config/config.yaml")
	if err != nil {
		log.Fatal("Config doesn't exist! ", err)
	}

	data := make([]byte, fi.Size())
	_, err = cf.Read(data)
	if err != nil {
		log.Fatal("Unable to read config data: ", err)
	}
	config := cfg.NewConfig()
	err = config.Unmarshal(data)
	if err != nil {
		log.Fatal("Unable to load config: ", err)
	}

	e := AuthFramework{Echo: echo.New()}
	e.config = config

	if _, err := os.Stat(config.Security.PrivateKeyPath); os.IsNotExist(err) {
		_, pub := e.GenerateKeyPair(config.Security.PrivateKeyPath, config.Security.BitSize)
		config.Security.PublicKeyPath = pub
		err = config.Save()
		if err != nil {
			log.Fatal("Unable to save config: ", err)
		}
	} else {
		e.KeyPair, err = LoadPrivateKey(config.Security.PrivateKeyPath)
		if err != nil {
			log.Fatal("Unable to load private key")
		}
		pk, err := LoadPublicKey(config.Security.PublicKeyPath)
		if err != nil {
			log.Fatal("Unable to load public key")
		}
		e.KeyPair.PublicKey = *pk
	}

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	CORSConfig := middleware.DefaultCORSConfig
	CORSConfig.AllowOrigins = []string{config.Customization.SiteURL}
	e.Use(middleware.CORSWithConfig(CORSConfig))
	e.Use(middleware.BodyLimit("10M"))
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(config.Security.CookieSecret))))

	t := &Template{
		templates: template.Must(template.ParseGlob("public/views/*.html")),
	}

	e.Renderer = t

	e.Static("/assets", "public/assets")

	// Routes
	e.GET("/", e.hello)
	e.GET("/publicKey", e.publicKey)
	e.GET("/auth/login", e.login)
	e.GET("/auth/process/:id", e.processLogin)
	e.GET("/auth/authorize", e.authCallback)
	e.GET("/authtest", e.authTest)
	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8989"
	}
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%s", port)))
}
