package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Membership struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty" validate:"required"`
	ID_Member primitive.ObjectID `json:"id_member,omitempty" validate:"required"`
	ID_Group  primitive.ObjectID `json:"id_group,omitempty" validate:"required"`
	IsAdmin   bool               `json:"is_admin,omitempty"`
}
