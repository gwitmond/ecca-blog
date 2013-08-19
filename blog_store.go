// Ecca Authentication Blog site
//
// Create a blog site that allows bloggers to establish a reputation (good or bad) based upon what they write.
// Note, everything anyone writes is signed by their private key.
// Unless one writes as Anonymous 
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main

// This file contains the data storage bits

// The definition of the Blog struct is in blog.go

import (
	//"log"
	//"os"
	"strconv"
        "github.com/coopernurse/gorp"
        "database/sql"
        _ "github.com/mattn/go-sqlite3"
)

type Datastore struct {
	Storename   string
	dbmap *gorp.DbMap
}

func DatastoreOpen(storename string) (*Datastore) {
        db, err := sql.Open("sqlite3", storename)
        check(err)
 	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	// set key to be unique. We can't allow multiple Id's anyway.
	// false -> no autogenerate of key.
        dbmap.AddTableWithName(Blog{}, "blogs").SetKeys(false, "Id")
	dbmap.CreateTables() // if not exists
        // dbmap.TraceOn("[gorp]", log.New(os.Stdout, "eccaCA:", log.Lmicroseconds)) 
	return &Datastore{
		Storename: storename,
		dbmap: dbmap,
	}
}


func (ds *Datastore) writeBlog(blog *Blog) {
	check(ds.dbmap.Insert(blog))
}

func (ds *Datastore) getBlogStr(Id string) (*Blog) {
	i, err := strconv.Atoi(Id)
	check(err)
	return ds.getBlog(i)
}

func (ds *Datastore) getBlog(Id int) (*Blog) {
	res, err := ds.dbmap.Get(Blog{}, Id)
        //log.Printf("Blog is %#v, err is %#v\n", res, err)
        check(err)
        if res == nil { return nil } //type  assert can't handle nil :-(
        return res.(*Blog)
}

func (ds *Datastore) getBlogs() (blogs []*Blog) {
	_, err := ds.dbmap.Select(&blogs, "SELECT * FROM blogs")
	check(err)
	return // blogs
}


