package edumasbackend

import (
	"context"
	"fmt"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func InsertUserdata(MongoConn *mongo.Database, username, role, password string) (InsertedID interface{}) {
	req := new(User)
	req.Username = username
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}

func InsertUserdataNew(MongoConn *mongo.Database, nik, nama, username, password, notelp, role string) (InsertedID interface{}) {
	req := new(UserNew)
	req.Nik = nik
	req.Nama = nama
	req.Username = username
	req.Password = password
	req.Notelp = notelp
	req.Role = role
	return InsertOneDoc(MongoConn, "usernew", req)
}	

func InsertAdmindata(MongoConn *mongo.Database, username, role, password string) (InsertedID interface{}) {
	req := new(Admin)
	req.Username = username
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "admin", req)
}

func DeleteUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	filter := bson.M{"username": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindAdmin(mongoconn *mongo.Database, collection string, admindata Admin) Admin {
	filter := bson.M{"username": admindata.Username}
	return atdb.GetOneDoc[Admin](mongoconn, collection, filter)
}

func IsExist(Tokenstr, PublicKey string) bool {
	id := watoken.DecodeGetId(PublicKey, Tokenstr)
	return id != ""
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CompareHashPass(userdata.Password, res.Password)
}

func IsPasswordValidUserNew(mongoconn *mongo.Database, collection string, userdata2 UserNew) bool {
	filter := bson.M{"username": userdata2.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CompareHashPass(userdata2.Password, res.Password)
}

func IsPasswordValidAdmin(mongoconn *mongo.Database, collection string, admindata Admin) bool {
	filter := bson.M{"username": admindata.Username}
	res := atdb.GetOneDoc[Admin](mongoconn, collection, filter)
	return CompareHashPass(admindata.Password, res.Password)
}

func MongoCreateConnection(MongoString, dbname string) *mongo.Database {
	MongoInfo := atdb.DBInfo{
		DBString: os.Getenv(MongoString),
		DBName:   dbname,
	}
	conn := atdb.MongoConnect(MongoInfo)
	return conn
}

func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func GetOneUser(MongoConn *mongo.Database, colname string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	data := atdb.GetOneDoc[User](MongoConn, colname, filter)
	return data
}

func GetOneAdmin(MongoConn *mongo.Database, colname string, admindata Admin) Admin {
	filter := bson.M{"username": admindata.Username}
	data := atdb.GetOneDoc[Admin](MongoConn, colname, filter)
	return data
}
