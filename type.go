package edumasbackend

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Role     string `json:"role,omitempty" bson:"role,omitempty"`
	Token    string `json:"token,omitempty" bson:"token,omitempty"`
	Private  string `json:"private,omitempty" bson:"private,omitempty"`
	Public   string `json:"public,omitempty" bson:"public,omitempty"`
}

type UserNew struct{
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	Username string `json:"username" bson:"username,omitempty"`
	Password string `json:"password" bson:"password,omitempty"`
	Notelp	 string `json:"notelp" bson:"notelp,omitempty"`
	Role     string `json:"role,omitempty" bson:"role,omitempty"`
	Token    string `json:"token,omitempty" bson:"token,omitempty"`
	Private  string `json:"private,omitempty" bson:"private,omitempty"`
	Public   string `json:"public,omitempty" bson:"public,omitempty"`
}

type Admin struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Role     string `json:"role,omitempty" bson:"role,omitempty"`
	Token    string `json:"token,omitempty" bson:"token,omitempty"`
	Private  string `json:"private,omitempty" bson:"private,omitempty"`
	Public   string `json:"public,omitempty" bson:"public,omitempty"`
} 

type Tanggapan struct {
	ID          	primitive.ObjectID 	`bson:"_id,omitempty"`
	Nik     		int            		`json:"nik" bson:"nik"`
    Description   	string 				`json:"description"`
    DateRespons  	string 				`json:"daterespons"`
}

type Credential struct {
	Status  bool   `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
	Data    []Report `bson:"data,omitempty" json:"data,omitempty"`
	Datas    []UserNew `bson:"datas,omitempty" json:"datas,omitempty"`
}

type ResponseDataUser struct {
	Status  bool   `json:"status" bson:"status"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
	Data    []User `json:"data,omitempty" bson:"data,omitempty"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}

type ResponseEncode struct {
	Message string `json:"message,omitempty" bson:"message,omitempty"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
}

type Payload struct {
	Id   primitive.ObjectID 	`json:"id"`
	Admin 		string				`json:"admin"`
	User 		string				`json:"user"`
	Tanggapan 	string				`json:"tanggapan"`
	Report		string				`json:"report"`
	Role 		string             	`json:"role"`
	Exp  		time.Time          	`json:"exp"`
	Iat  		time.Time          	`json:"iat"`
	Nbf  		time.Time          	`json:"nbf"`
}

type Report struct {
	ID          	primitive.ObjectID 	`bson:"_id,omitempty" json:"_id,omitempty"`
	Nik     		int            		`json:"nik" bson:"nik" json:"nik,omitempty`
	Nama			string				`json:"nama" bson:"nama" json:"nama,omitempty`
    Title         	string 				`json:"title" bson:"title" json:"title,omitempty`
    Description   	string 				`json:"description" bson:"description" json:"description,omitempty`
    DateOccurred  	string 				`json:"dateOccurred" bson:"dateOccured" json:"dataOccurred,omitempty`
	Image       	string             	`json:"image" bson:"image" json:"image,omitempty`
	Tanggapan		string				`json:"tanggapan" bson:"tanggapan" json:"tanggapan,omitempty`
	Status      	bool               	`json:"status" bson:"status" json:"status,omitempty`
}

type Contact struct {
	ID      int    `json:"id" bson:"id"`
	Name    string `json:"title" bson:"title"`
	Subject string `json:"description" bson:"description"`
	Alamat  string `json:"alamat" bson:"alamat"`
	Website string `json:"website" bson:"website"`
	Message string `json:"image" bson:"image"`
	Email   string `json:"email" bson:"email"`
	Phone   string `json:"phone" bson:"phone"`
	Status  bool   `json:"status" bson:"status"`
}

