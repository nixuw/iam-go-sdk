// Package webflow is the framework-neutral contract between the core
// package and the HTTP adapters (iamhttp, iamfiber) for the sign-in handlers.
// The core implements LoginEngine; an adapter translates between its
// framework's request and response types and the plain types defined here.
package webflow

import (
	"context"
	"net/http"
)

// Request is what the sign-in flow reads from an incoming HTTP request.
type Request struct {
	Method   string
	Path     string
	RawQuery string
	// Header returns the first value of a request header.
	Header func(name string) string
	// Cookie returns the value of a request cookie, or "".
	Cookie func(name string) string
}

// Response is what the sign-in flow wants sent back.
type Response struct {
	// Status is the HTTP status. With a 3xx status, Location is set.
	Status   int
	Location string
	// Cookies are to be set on the response, whatever the status.
	Cookies []*http.Cookie
	// Err is set when the request was refused or failed. Code and
	// Description are a safe rendition of it for the default error body.
	Err         error
	Code        string
	Description string
}

// LoginEngine performs the sign-in flow with the built-in local session.
type LoginEngine interface {
	// Start begins a sign-in and redirects to IAM.
	Start(ctx context.Context, r *Request) *Response
	// Callback completes a sign-in and redirects to the page it started from.
	Callback(ctx context.Context, r *Request) *Response
	// Logout ends the local session and redirects to IAM's logout endpoint.
	Logout(ctx context.Context, r *Request) *Response
	// Authenticate returns the signed-in user of the request (a *iam.User).
	// Otherwise refuse says how to answer: a redirect to loginPath for a
	// page request, 401 for an API request.
	Authenticate(ctx context.Context, r *Request, loginPath string) (user any, refuse *Response)
}

// Engine returns the LoginEngine of a *iam.Login. It is set by package iam.
var Engine func(login any) LoginEngine
