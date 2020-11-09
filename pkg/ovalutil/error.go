package ovalutil

import "errors"

var (
	errTestSkip   = errors.New("skip this test")
	errStateSkip  = errors.New("skip this state")
	errObjectSkip = errors.New("skip this object")
)
