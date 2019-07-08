package main

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func (f *authFramework) processLogin(c echo.Context) error {
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

	uri := f.config.Providers[id].AuthCodeURL(randomString)

	return c.Redirect(http.StatusTemporaryRedirect, uri)
}

func (f *authFramework) authCallback(c echo.Context) error {
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

	redirectUri := sess.Values["redirect"].(string)
	if redirectUri == "" {
		// fall back to config redirect
		redirectUri = f.config.Providers[id].RedirectURL
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

	return c.Redirect(http.StatusTemporaryRedirect, redirectUri+"?token="+tokenString)
}

func (f *authFramework) authTest(c echo.Context) error {
	token := c.QueryParam("token")
	return c.JSON(http.StatusOK, map[string]string{"message": "OK", "token": token})
}

func (f *authFramework) index(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"app": "gangway", "version": Version})
}

func (f *authFramework) publicKey(c echo.Context) error {
	asn1Bytes, err := asn1.Marshal(f.KeyPair.PublicKey)
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	return c.Blob(http.StatusOK, "application/x-pem-file", pem.EncodeToMemory(pemkey))
}

func (f *authFramework) login(c echo.Context) error {
	redirectURI := c.Param("redirect")

	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"msg": "redirect URI is invalid"})
		}
		allowed := false
		for i := 0; i < len(f.config.Security.AllowedDomains); i++ {
			if f.config.Security.AllowedDomains[i] == u.Host {
				allowed = true
				break
			}
		}

		if !allowed {
			return c.JSON(http.StatusNotAcceptable, map[string]string{"msg": "redirect URI isn't allowed"})
		}

		sess, _ := session.Get("session", c)
		sess.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
		}
		sess.Values["redirect"] = redirectURI
		err = sess.Save(c.Request(), c.Response())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "unable to store session data"})
		}
	}
	return c.Render(http.StatusOK, "login", f.config)
}
