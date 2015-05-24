package main

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

//User carries user data for exchange, especially in views
type User struct {
	ID         string `json:"id" bson:",omitempty"`
	PID        string `json:"pid" bson:",omitempty"`
	Provider   string `json:"provider"`
	Password   string
	Permission string `json:"permission" bson:"permission,omitempty"`
	Image      string `json:"image"`
	Name       string `json:"name"`
	Link       string `json:"link"`
	Gender     string `json:"gender"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
}

type poll struct {
	Timestamp time.Time
	Pname     string
	Powner    string
	Ptype     string
	Images    []Images
	Location GeoJson `json:"location"`
	Answers   []struct {
		ID    string
		Text  string
		Image string
	}
}

type GeoJson struct {
	Type        string    `json:"type"`
	Coordinates []float64 `json:"coordinates"`
}

//Images makes dealing with thumbnails and full size images easier
type Images struct {
	Thumb string
	Full  string
}

//lookUp holds reference data liking a providers collection eith the users
//collection
type lookUp struct {
	Provider    string
	ProviderUID string
	UserID      string
}

type place struct {
	ID           bson.ObjectId `bson:"_id,omitempty"`
	Approved     int
	Featured     int
	Slug         string
	Location     string
	State        string
	Budget       string
	Service      []string
	Name         string
	Overview     string
	Address      string
	WorkingHours string
	Phone        string
	PriceRange   string
	Owner        string
	Timestamp    time.Time
	Images       []Images
	Rating       int
	TotalReviews int
	ReviewsCount int
}
