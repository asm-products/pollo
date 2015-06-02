package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

//Authenticate check if user exists if not create a new user document NewUser function is called within this function. note the user struct being passed
//to this function should alredi contain a self generated objectid
func (c *appContext) Authenticate(user *User, provider string) (*User, error) {
	log.Println("Authenticate")
	result := User{}
	C := c.db.C("users")

	log.Println(user.PID)
	log.Println(provider)

	change := mgo.Change{
		Update: bson.M{"$set": bson.M{
			"pid":   user.PID,
			"name":  user.Name,
			"email": user.Email,
			"image": user.Image,
		},
		},
		Upsert:    true,
		ReturnNew: true,
	}
	info, err := C.Find(bson.M{"pid": user.PID, "provider": provider}).Apply(change, &result)
	log.Println(info)
	log.Println(result)

	if err != nil {
		return &result, err
	}
	//if result.Provider != "" {
	//	return &result, nil
	//}

	//return c.NewUser(user, provider)
	return &result, nil
}

//NewUser is for adding a new user to the database. Please note that what you pass to the function is a pointer to the actual data, note the data its self. ie newUser(&NameofVariable)
func (c *appContext) NewUser(data *User, socialProvider string) (*User, error) {

	collection := c.db.C("users")
	data.ID = bson.NewObjectId().Hex()
	data.Provider = socialProvider

	err := collection.Insert(data)
	if err != nil {
		log.Println(err)
		return data, err
	}

	return data, nil
}

func (c *appContext) newPollHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := userget(r)
	polls := c.db.C("polls")
	p := poll{}

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		log.Println(err)
	}
	index := mgo.Index{
		Key:  []string{"$2dsphere:location"},
		Bits: 26,
	}
	err = polls.EnsureIndex(index)
	if err != nil {
		log.Println(err)
	}

	p.Timestamp = time.Now()
	p.Powner = user.ID

	err = polls.Insert(p)

	if err != nil {
		log.Println(err)
		err = json.NewEncoder(w).Encode(struct {
			Message string
		}{err.Error()})

		if err != nil {
			log.Println(err)
		}

	}
	err = json.NewEncoder(w).Encode(struct {
		Message string
	}{"Successful"})
	if err != nil {
		log.Println(err)
	}

}
func (c *appContext) pollResultsHandler(w http.ResponseWriter, r *http.Request) {
	lat, err := strconv.ParseFloat(r.URL.Query().Get("lat"), 64)
	if err != nil {
		log.Println(err)

	}
	long, err := strconv.ParseFloat(r.URL.Query().Get("long"), 64)
	if err != nil {
		log.Println(err)
	}
	scope := 100000
	polls := c.db.C("polls")
	results := []poll{}
	err = polls.Find(bson.M{
		"location": bson.M{
			"$nearSphere": bson.M{
				"$geometry": bson.M{
					"type":        "Point",
					"coordinates": []float64{long, lat},
				},
				"$maxDistance": scope,
			},
		},
	}).All(&results)

	if err != nil {
		log.Println(err)
	}
	log.Println(results)
	err = json.NewEncoder(w).Encode(results)
	if err != nil {
		log.Println(err)
	}
}

func userget(r *http.Request) (User, error) {
	u := context.Get(r, "User")
	var user User
	err := mapstructure.Decode(u, &user)
	if err != nil {
		return user, err

	}
	return user, nil

}
