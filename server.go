// Copyright 2016 Simon HEGE. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt" //TODO: rearchitecture so that we can log easily
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

// Config provides the configuration for the API server
type Config struct {
	Addr string //The address to listen on

	SigningKey      []byte
	SigningDuration time.Duration
}

type Chain []func(next http.Handler) http.Handler

func (c Chain) Handler(h http.Handler) http.Handler {
	for i := len(c) - 1; i >= 0; i-- {
		h = c[i](h)
	}
	return h
}

// Server contains instance details for the server
type Server struct {
	CheckPassword      func(ctx context.Context, userID, password string) error
	cfg                Config
	mux                *mux.Router
	middlewares        Chain
	privateMiddlewares Chain
}

// New returns a new instance of the server based on the specified configuration.
func New(cfg Config) *Server {
	s := Server{
		CheckPassword: func(ctx context.Context, userID, password string) error {
			return errors.New("not implemented")
		},
		cfg: cfg,
		mux: mux.NewRouter(),
	}

	//TODO: add global middlewares, based on cfg

	s.privateMiddlewares = append(s.privateMiddlewares, s.AuthenticatedFilter())

	return &s
}

//Login sets the path to authenticate
func (s *Server) Login(loginPath string) { //TODO add refreshPath or switch to dex
	s.Public(NewJSONRoute("GET", loginPath, s.loginHandler))
	s.Public(NewJSONRoute("POST", loginPath, s.loginHandler))
}

func (s *Server) loginHandler(req *http.Request) (interface{}, error) {

	token, err := s.Authenticate(req)
	if err != nil {
		return nil, errors.Wrap(err, "Authenticate failed")
	}

	return struct {
		Token string `json:"token"`
	}{
		Token: token,
	}, nil
}

//Public adds a publicly available route to the server
func (s *Server) Public(route Route) {
	s.addRouteWithChain(s.middlewares, route)
}

//Private adds a private route to the server. Only authenticated users can access it.
func (s *Server) Private(route Route) {
	s.addRouteWithChain(s.privateMiddlewares, route)
}

// addRouterWithChain adds one or multiple routers for the server.New
//The given middleware chain will be added to each route.
func (s *Server) addRouteWithChain(chain Chain, r Route) {

	s.mux.Handle(r.Path(), chain.Handler(r.Handler())).Methods(r.Method())

}

//Handler returns the handler provided by the server
func (s *Server) Handler() http.Handler {
	return handlers.CORS(handlers.AllowedHeaders([]string{"Authorization", "Content-Type"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"}))(s.mux)
}

//Run is a convenience function that runs the server as an HTTP server.
func (s *Server) Run() error {
	return http.ListenAndServe(s.cfg.Addr, s.Handler())
}

//ErrInvalidToken is raised when the token is not valid
var ErrInvalidToken = errors.New("Invalid token. Please try to reconnect.")

//ErrExpiredToken is raised when the token has expired
var ErrExpiredToken = errors.New("Expired token. Please try to reconnect.")

//Param extract an URL parameter
func Param(r *http.Request, name string) string {
	return mux.Vars(r)[name]
}

func (s *Server) validateToken(tokenString string) (*jwt.Token, error) {

	// validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.cfg.SigningKey, nil
	})

	// branch out into the possible error from signing
	switch err.(type) {

	case nil: // no error
		if !token.Valid { // but may still be invalid
			return nil, ErrInvalidToken
		}

	case *jwt.ValidationError: // something was wrong during the validation
		vErr := err.(*jwt.ValidationError)

		switch vErr.Errors {
		case jwt.ValidationErrorExpired:
			return nil, ErrExpiredToken

		default:
			return nil, err
		}

	default: // something else went wrong
		return nil, err
	}

	return token, nil
}

//Route defines an individual API route in the server.
type Route interface {
	// Handler returns the raw function to create the http handler.
	Handler() http.Handler
	// Method returns the http method that the route responds to.
	Method() string
	// Path returns the subpath where the route responds to.
	Path() string
}

func handleError(r *http.Request, w http.ResponseWriter, err error) {

	cause := errors.Cause(err)

	if ok, url := IsRedirect(cause); ok {
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		return
	}

	if IsNotFound(cause) {
		http.Error(w, "Data not found", http.StatusNotFound)
		return
	}

	if IsNotAuthorized(cause) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

//NewJSONRoute creates a new route sending back JSON
func NewJSONRoute(method, path string, handler func(r *http.Request) (interface{}, error)) Route {

	statusCode := http.StatusOK
	if method == "POST" {
		statusCode = http.StatusAccepted
	}

	return NewRoute(method, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		data, err := handler(r)

		if err != nil {
			handleError(r, w, err)
			return
		}

		if data == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(statusCode)
			encoder := json.NewEncoder(w)
			err := encoder.Encode(data)
			if err != nil {
				fmt.Println(err)
				handleError(r, w, err)
				return
			}
		}
	}))
}

//NewRoute creates a new route
func NewRoute(method, path string, handler http.Handler) Route {
	return basicRoute{
		m: method,
		p: path,
		h: handler,
	}
}

//NewRouteFunc creates a new route with an handler function
func NewRouteFunc(method, path string, handler http.HandlerFunc) Route {
	return basicRoute{
		m: method,
		p: path,
		h: handler,
	}
}

type basicRoute struct {
	m string
	p string
	h http.Handler
}

func (r basicRoute) Handler() http.Handler {
	return r.h
}
func (r basicRoute) Method() string {
	return r.m
}
func (r basicRoute) Path() string {
	return r.p
}

type handlerC struct {
	http.Handler
}

func (h handlerC) ServeHTTPC(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	h.ServeHTTP(w, r)
}

//NewStaticFilesRoute creates a new route that returns static files
func NewStaticFilesRoute(pathPrefix string, root http.FileSystem) Route {

	if len(pathPrefix) > 0 && pathPrefix[len(pathPrefix)-1] == '/' {
		pathPrefix = pathPrefix[:len(pathPrefix)-1]
	}

	h := http.StripPrefix(pathPrefix, http.FileServer(root))

	return NewRoute("GET", pathPrefix+"/*path", handlerC{h})
}

//NewRedirectRoute creates a new route that redirect to a new URL
func NewRedirectRoute(from, to string) Route {
	return NewRoute("GET", from, handlerC{http.RedirectHandler(to, http.StatusMovedPermanently)})
}

//Authenticate returns a signed token if the request contains valid userID and password
func (s *Server) Authenticate(r *http.Request) (string, error) {
	userID := r.FormValue("userID")
	password := r.FormValue("password")

	if len(userID) == 0 {
		if r.Body != nil {
			if body, err := ioutil.ReadAll(r.Body); err == nil {
				defer r.Body.Close()
				var jsonItem struct {
					UserID   string `json:"userID"`
					Password string `json:"password"`
				}
				if err := json.Unmarshal(body, &jsonItem); err == nil {
					userID = jsonItem.UserID
					password = jsonItem.Password
				}
			}
		}
	}

	ctx := r.Context()

	err := s.CheckPassword(ctx, userID, password)
	if err != nil {
		return "", errors.Wrap(err, "password check failed")
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"userId": userID,
		"exp":    time.Now().Add(s.cfg.SigningDuration).Unix(),
	})

	// Sign and get the complete encoded token as a string
	return token.SignedString(s.cfg.SigningKey)
}

//CheckAuthorization returns the decoded valid token if any
func (s *Server) CheckAuthorization(r *http.Request) (*jwt.Token, error) {

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
		return nil, ErrInvalidToken
	}
	tokenString := bearerString[len("Bearer "):]

	token, err := s.validateToken(tokenString)
	if err != nil {
		return nil, err
	}

	return token, nil
}

type key int

const userIDKey key = 0

func newContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

//GetUserID returns the current ID of the logged in user, if any
func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(userIDKey).(string)
	if !ok {
		return "", errors.New("Invalid user ID")
	}

	return userID, nil
}

// AuthenticatedFilter filters logged in users. Users with an invalid session are redirected to the loginURL.
func (s *Server) AuthenticatedFilter( /*loginURL string*/ ) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			ctx := r.Context()

			token, err := s.CheckAuthorization(r)
			if err == ErrInvalidToken || err == ErrExpiredToken { //TODO: add redirect
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			} else if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			signedString, err := token.SignedString(s.cfg.SigningKey)
			http.SetCookie(w, &http.Cookie{
				Name:  "bearer-token",
				Value: signedString,
				Path:  "/pages/",
			})

			//Store user in new context
			claims := token.Claims.(jwt.MapClaims)
			userID, ok := claims["userId"].(string)
			if !ok {
				http.Error(w, "Invalid user ID in token", http.StatusInternalServerError)
				return
			}
			ctx = newContextWithUserID(ctx, userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
