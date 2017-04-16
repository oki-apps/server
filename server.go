// Copyright 2016 Simon HEGE. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

// Config provides the configuration for the API server
type Config struct {
	Addr                string //The address to listen on
	OpenIDConnectIssuer string //The issuer of authorisation tokens
}

// Server contains instance details for the server
type Server struct {
	cfg Config
	mux *mux.Router
}

// New returns a new instance of the server based on the specified configuration.
func New(cfg Config) (*Server, error) {
	s := Server{
		cfg: cfg,
		mux: mux.NewRouter(),
	}

	return &s, nil
}

//Router allow route registration on the server
func (s *Server) Router() *mux.Router {
	return s.mux
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

//Param extract an URL parameter
func Param(r *http.Request, name string) string {
	return mux.Vars(r)[name]
}
