// Copyright 2016 Simon HEGE. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt" //TODO: rearchitecture so that we can log easily
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

// Config provides the configuration for the API server
type Config struct {
	Addr                string //The address to listen on
	OpenIDConnectIssuer string //The issuer of authorisation tokens
}

type chain []func(next http.Handler) http.Handler

func (c chain) Handler(h http.Handler) http.Handler {
	for i := len(c) - 1; i >= 0; i-- {
		h = c[i](h)
	}
	return h
}

// Server contains instance details for the server
type Server struct {
	cfg                Config
	mux                *mux.Router
	middlewares        chain
	privateMiddlewares chain
}

// New returns a new instance of the server based on the specified configuration.
func New(cfg Config) (*Server, error) {
	s := Server{
		cfg: cfg,
		mux: mux.NewRouter(),
	}

	//TODO: add global middlewares, based on cfg
	authFilter, err := s.AuthenticatedFilter()
	if err != nil {
		return nil, err
	}

	s.privateMiddlewares = append(s.privateMiddlewares, authFilter)

	return &s, nil
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
func (s *Server) addRouteWithChain(chain chain, r Route) {

	if r.IsPrefix() {
		s.mux.PathPrefix(r.Path()).Handler(chain.Handler(r.Handler())).Methods(r.Method())
	} else {
		s.mux.Handle(r.Path(), chain.Handler(r.Handler())).Methods(r.Method())
	}
}

//Handler returns the handler provided by the server
func (s *Server) Handler() http.Handler {
	return handlers.CORS(
		handlers.AllowedHeaders([]string{"Authorization", "Content-Type"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"}),
	)(s.mux)
}

//Run is a convenience function that runs the server as an HTTP server.
func (s *Server) Run() error {
	return http.ListenAndServe(s.cfg.Addr, s.Handler())
}

//ErrInvalidToken is raised when the token is not valid
var ErrInvalidToken = errors.New("Invalid token. Please try to reconnect.")

//Param extract an URL parameter
func Param(r *http.Request, name string) string {
	return mux.Vars(r)[name]
}

//Route defines an individual API route in the server.
type Route interface {
	// Handler returns the raw function to create the http handler.
	Handler() http.Handler
	// Method returns the http method that the route responds to.
	Method() string
	// Path returns the subpath where the route responds to.
	Path() string
	// IsPrefix returns wheter the rout is for a single path (false) or a wildcard
	IsPrefix() bool
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
	m      string
	p      string
	h      http.Handler
	prefix bool
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
func (r basicRoute) IsPrefix() bool {
	return r.prefix
}

//NewStaticFilesRoute creates a new route that returns static files
func NewStaticFilesRoute(pathPrefix string, root http.FileSystem) Route {

	if len(pathPrefix) > 0 && pathPrefix[len(pathPrefix)-1] == '/' {
		pathPrefix = pathPrefix[:len(pathPrefix)-1]
	}

	h := http.StripPrefix(pathPrefix, http.FileServer(root))

	return basicRoute{
		m:      "GET",
		p:      pathPrefix + "/",
		h:      h,
		prefix: true,
	}
}

//NewRedirectRoute creates a new route that redirect to a new URL
func NewRedirectRoute(from, to string) Route {
	return NewRoute("GET", from, http.RedirectHandler(to, http.StatusMovedPermanently))
}

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

type key int

const userInfoKey key = 0

func newContextWithUserInfo(ctx context.Context, u userInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, u)
}

//UserInfo contains basic information for an authenticated user
type UserInfo interface {
	ID() string
	DisplayName() string
	Email() string
}

type userInfo struct {
	subject string
	name    string
	email   string
}

func (u userInfo) ID() string {
	return u.subject
}
func (u userInfo) DisplayName() string {
	return u.name
}
func (u userInfo) Email() string {
	return u.email
}

//GetUserInfo returns the current ID of the logged in user, if any
func GetUserInfo(ctx context.Context) (UserInfo, error) {
	userInfo, ok := ctx.Value(userInfoKey).(userInfo)
	if !ok {
		return nil, errors.New("Invalid user ID")
	}

	return userInfo, nil
}

// AuthenticatedFilter filters logged in users
func (s *Server) AuthenticatedFilter() (func(next http.Handler) http.Handler, error) {

	provider, err := oidc.NewProvider(context.Background(), s.cfg.OpenIDConnectIssuer)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(oidc.VerifyExpiry())

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
