package main

import (
	"context"
	"encoding/hex"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"net/http"
	"strconv"
	"time"
)

func (f *AuthFramework) ProcessLogin(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invalid provider"})
	}
	if id < 0 || id >= len(f.config.Providers) {
		return c.JSON(http.StatusNotFound, map[string]string{"message": "provider does not exist"})
	}

	randomBytes, _ := uuid.New().MarshalBinary()
	randomString := hex.EncodeToString(randomBytes)

	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	sess.Values["state"] = randomString
	sess.Values["provider"] = strconv.Itoa(id)

	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "unable to store session data"})
	}

	url := f.config.Providers[id].AuthCodeURL(randomString)

	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func (f *AuthFramework) AuthCallback(c echo.Context) error {
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	state := sess.Values["state"]
	id, err := strconv.Atoi(sess.Values["provider"].(string))

	userState := c.QueryParam("state")

	if userState != state {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "invalid state"})
	}

	code := c.QueryParam("code")
	token, err := f.config.Providers[id].Exchange(context.Background(), code)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "code exchange failed"})
	}

	t := jwt.New(jwt.GetSigningMethod("RS256"))

	claims := t.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	claims["token"] = token.AccessToken
	claims["authSource"] = f.config.Providers[id].Name
	tokenString, err := t.SignedString(f.KeyPair)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to sign token"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "OK", "token": tokenString})
}
