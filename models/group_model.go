package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Group struct {
	ID        primitive.ObjectID `json:"id,omitempty"`
	NamaGroup string             `json:"namaGroup,omitempty" validate:"required"`
	RefKey    string             `json:"refKey,omitempty" validate:"required"`
}
