// Copyright 2016 Simon HEGE. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/pkg/errors"
)

//IsNotFound returns whether the error cause is that something was not found
func IsNotFound(err error) bool {
	nfe, ok := errors.Cause(err).(NotFound)
	return ok && nfe.IsNotFound()
}

//NotFound is the interface that wraps the IsNotFound nethod
type NotFound interface {
	IsNotFound() bool
}

//IsNotAuthorized returns whether the error cause is that there was an attempt top perform a not authorized action
func IsNotAuthorized(err error) bool {
	nae, ok := errors.Cause(err).(NotAuthorized)
	return ok && nae.IsNotAuthorized()
}

//NotAuthorized is the interface that wraps the IsNotAuthorized nethod
type NotAuthorized interface {
	IsNotAuthorized() bool
}

//Redirect is the interface to be implemented by errors that requires a redirecton to a new URL
type Redirect interface {
	RedirectURL() string
}

//IsRedirect returns whether the error cause redirecton a redirecton to a new URL
func IsRedirect(err error) (bool, string) {
	re, ok := errors.Cause(err).(Redirect)
	if ok {
		url := re.RedirectURL()
		return len(url) > 0, url
	}
	return false, ""

}
