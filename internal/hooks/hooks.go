// Package hooks gives the tests of this module control over time inside SDK
// instances. It is internal: applications cannot reach it, and nothing in it
// is global state — every hook acts on one instance.
package hooks

import (
	"context"
	"time"
)

// SetClock replaces the clock of a *iam.Verifier, *iam.Caller or *iam.Login.
// It is set by package iam.
var SetClock func(instance any, now func() time.Time)

// SetSleep replaces the wait between retries of a *iam.Caller. It is set by
// package iam.
var SetSleep func(instance any, sleep func(context.Context, time.Duration) error)
