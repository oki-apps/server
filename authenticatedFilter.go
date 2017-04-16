package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/coreos/go-oidc"
)

//ErrInvalidToken is raised when the token is not valid
var ErrInvalidToken = errors.New("Invalid token. Please try to reconnect.")

//GetRawIDToken returns the raw token if any
func GetRawIDToken(r *http.Request) (string, error) {

	//Retrieve JWT from Authorization header (or auth form parameter)
	bearerString := r.Header.Get("Authorization")
	if len(bearerString) == 0 {
		formBearer := r.FormValue("auth")
		if len(formBearer) > 0 {
			bearerString = "Bearer " + formBearer
		} else {
			cookie, err := r.Cookie("bearer-token")
			if err == nil && cookie != nil && len(cookie.Value) > 0 {
				bearerString = "Bearer " + cookie.Value
			}
		}
	}
	if len(bearerString) < len("Bearer ") {
		return "", ErrInvalidToken
	}
	return bearerString[len("Bearer "):], nil
}

// AuthenticatedFilter filters logged in users
func AuthenticatedFilter(openIDConnectIssuer string) (func(next http.Handler) http.Handler, error) {

	provider, err := oidc.NewProvider(context.Background(), openIDConnectIssuer)
	if err != nil {
		return nil, err
	}
	config := oidc.Config{
		SkipClientIDCheck: true,
		SkipNonceCheck:    true,
	}
	verifier := provider.Verifier(&config)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			ctx := r.Context()
			rawIDToken, err := GetRawIDToken(r)
			if err == ErrInvalidToken {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			} else if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:  "bearer-token",
				Value: rawIDToken,
				Path:  "/pages/",
			})

			var claims struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			}
			if err := idToken.Claims(&claims); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			//Store user in new context
			ctx = newContextWithUserInfo(ctx, userInfo{
				subject: idToken.Subject,
				name:    claims.Name,
				email:   claims.Email,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}
