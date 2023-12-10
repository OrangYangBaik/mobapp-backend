package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Group struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	NamaGroup string             `json:"namaGroup,omitempty" validate:"required"`
	RefKey    string             `json:"refKey,omitempty" validate:"required"`
	Status    bool               `json:"status,omitempty" validate:"required"`
}
