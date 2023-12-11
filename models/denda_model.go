package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Denda struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	ID_Member primitive.ObjectID `bson:"id_member,omitempty" json:"id_member,omitempty"`
	ID_Group  primitive.ObjectID `bson:"id_group,omitempty" json:"id_group,omitempty"`
	Hari      string             `bson:"hari,omitempty" json:"hari,omitempty" validate:"required"`
	Nominal   int                `bson:"nominal,omitempty" json:"nominal,omitempty" validate:"required"`
	Desc      string             `bson:"desc,omitempty" json:"desc,omitempty" validate:"required"`
	Link      string             `bson:"path,omitempty" json:"path,omitempty"`
	IsPaid    bool               `bson:"is_paid" json:"is_paid"`
}
