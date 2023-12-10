package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Denda struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	ID_Member primitive.ObjectID `json:"id_member,omitempty" validate:"required"`
	ID_Group  primitive.ObjectID `json:"id_group,omitempty" validate:"required"`
	Hari      string             `json:"hari,omitempty" validate:"required"`
	Nominal   string             `json:"nominal,omitempty" validate:"required"`
	Desc      string             `json:"desc,omitempty" validate:"required"`
	IsPaid    bool               `json:"ispaid,omitempty" validate:"required"`
}
