package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Member struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Nama     string             `json:"nama,omitempty" validate:"required"`
	NIM      string             `json:"nim,omitempty" validate:"required"`
	Password string             `json:"password,omitempty" validate:"required"`
	Email    string             `json:"email,omitempty" validate:"required"`
	Prodi    string             `json:"prodi,omitempty" validate:"required"`
	Angkatan string             `json:"angkatan,omitempty" validate:"required"`
}
