// Eccentric Authentication Blog site
//
// Create a blog site that allows bloggers to establish a reputation (good or bad) based upon what they write.
// Note, everything anyone writes is signed by their private key.
// Unless one writes as Anonymous Coward.

// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.


// Test code.

package main

import (
        "testing"
        "testing/quick"
        //"bytes"
        MathRand   "math/rand"
        "time"
)

// simple test to check correct working of datastore routines
func TestMemoryDB(t *testing.T) {
	// sets ds in main.go
	ds = DatastoreOpen(":memory:")

	testStoreRetrieve := func(c Blog) bool {
		// store
		ds.writeBlog(&c)

		// retrieve
		res := ds.getBlog(c.Id)

		return c == *res
	}
	err := quick.Check(testStoreRetrieve,
		&quick.Config{
			MaxCount: 10,
			Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
		})
	if err != nil {
		t.Error(err)
	}
}
