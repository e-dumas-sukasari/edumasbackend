package edumasbackend

import (
	"context"
	"fmt"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// crud
func GetAllDocs(db *mongo.Database, col string, docs interface{}) interface{} {
	collection := db.Collection(col)
	filter := bson.M{}
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		return fmt.Errorf("error GetAllDocs %s: %s", col, err)
	}
	err = cursor.All(context.TODO(), &docs)
	if err != nil {
		return err
	}
	return docs
}

func UpdateOneDoc(id primitive.ObjectID, db *mongo.Database, col string, doc interface{}) (err error) {
	filter := bson.M{"_id": id}
	result, err := db.Collection(col).UpdateOne(context.Background(), filter, bson.M{"$set": doc})
	if err != nil {
		return fmt.Errorf("error update: %v", err)
	}
	if result.ModifiedCount == 0 {
		err = fmt.Errorf("tidak ada data yang diubah")
		return
	}
	return nil
}

func DeleteOneDoc(_id primitive.ObjectID, db *mongo.Database, col string) error {
	collection := db.Collection(col)
	filter := bson.M{"_id": _id}
	result, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		return fmt.Errorf("error deleting data for ID %s: %s", _id, err.Error())
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("data with ID %s not found", _id)
	}

	return nil
}

// Admin
func CreateNewAdminRole(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPass(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

// User
func CreateNewUserRole(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPass(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateNewUserRoleNew(mongoconn *mongo.Database, collection string, userdata UserNew) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPass(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

//user
func CreateUserAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) error {
	// Hash the password before storing it
	hashedPassword, err := HashPass(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	userdata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, userdata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

//admin
func CreateAdminAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, admindata Admin) error {
	// Hash the password before storing it
	hashedPassword, err := HashPass(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Create a token for the admin
	tokenstring, err := watoken.Encode(admindata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	admindata.Token = tokenstring

	// Insert the admin data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, admindata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func CreateResponse(status bool, message string, data interface{}) Response {
	response := Response{
		Status:  status,
		Message: message,
		Data:    data,
	}
	return response
}

func CreateUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPass(userdata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	userid := userdata.Username
	tokenstring, err := watoken.Encode(userid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	useridstring := watoken.DecodeGetId(publicKey, tokenstring)
	if useridstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(useridstring)
	userdata.Private = privateKey
	userdata.Public = publicKey
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateAdmin(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPass(admindata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	adminid := admindata.Username
	tokenstring, err := watoken.Encode(adminid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	adminidstring := watoken.DecodeGetId(publicKey, tokenstring)
	if adminidstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(adminidstring)
	admindata.Private = privateKey
	admindata.Public = publicKey
	admindata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

func GetAllUser(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
}

func FindUserUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{
		"username": userdata.Username,
	}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

// Report
func CreateNewReport(mongoconn *mongo.Database, collection string, reportdata Report) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, reportdata)
}

// Report function
func CreateReport(mongoconn *mongo.Database, collection string, reportdata Report) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, reportdata)
}

// Report function
func insertReport(mongoconn *mongo.Database, collection string, reportdata Report) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, reportdata)
}

func DeleteReport(mongoconn *mongo.Database, collection string, reportdata Report) interface{} {
	filter := bson.M{"nik": reportdata.Nik}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedReport(mongoconn *mongo.Database, collection string, filter bson.M, reportdata Report) interface{} {
	updatedFilter := bson.M{"nik": reportdata.Nik}
	return atdb.ReplaceOneDoc(mongoconn, collection, updatedFilter, reportdata)
}

func GetAllReport(mongoconn *mongo.Database, collection string) []Report {
	report := atdb.GetAllDoc[[]Report](mongoconn, collection)
	return report
}

func FindReport(mongoconn *mongo.Database, collection string, reportdata Report) Report {
	filter := bson.M{
		"nik": reportdata.Nik,
	}
	return atdb.GetOneDoc[Report](mongoconn, collection, filter)
}

func GetAllReportID(mongoconn *mongo.Database, collection string, reportdata Report) Report {
	filter := bson.M{
		"nik":     		reportdata.Nik,
	}
	reportID := atdb.GetOneDoc[Report](mongoconn, collection, filter)
	return reportID
}

func GetOneReportNik(mongoconn *mongo.Database, collection string, reportdata Report) Report {
	filter := bson.M{"nik": reportdata.Nik}
	return atdb.GetOneDoc[Report](mongoconn, collection, filter)
}

func GetOneReport(mongoconn *mongo.Database, collection string, reportdata Report) Report {
	filter := bson.M{"nik": reportdata.Nik}
	return atdb.GetOneDoc[Report](mongoconn, collection, filter)
}

// func GetOneReportData(mongoconn *mongo.Database, colname, Nik string) (dest Report) {
// 	filter := bson.M{"nik": Nik}
// 	dest = atdb.GetOneDoc[Report](mongoconn, colname, filter)
// 	return
// }

func GetOneReportData(mongoconn *mongo.Database, collname string, reportdata Report) Report {
	filter := bson.M{"nik": reportdata.Nik}	
	return atdb.GetOneDoc[Report](mongoconn, collname, filter)
}

// Function Tanggapan

// Tanggapan
func CreateNewTanggapan(mongoconn *mongo.Database, collection string, tanggapandata Tanggapan) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, tanggapandata)
}

// Tanggapan function
func insertTanggapan(mongoconn *mongo.Database, collection string, tanggapandata Tanggapan) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, tanggapandata)
}

func DeleteTanggapan(mongoconn *mongo.Database, collection string, tanggapandata Tanggapan) interface{} {
	filter := bson.M{"nik": tanggapandata.Nik}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func UpdatedTanggapan(mongoconn *mongo.Database, collection string, filter bson.M, tanggapandata Tanggapan) interface{} {
	updatedFilter := bson.M{"nik": tanggapandata.Nik}
	return atdb.ReplaceOneDoc(mongoconn, collection, updatedFilter, tanggapandata)
}

func GetAllTanggapan(mongoconn *mongo.Database, collection string) []Tanggapan {
	tanggapan := atdb.GetAllDoc[[]Tanggapan](mongoconn, collection)
	return tanggapan
}

func GetOneTanggapan(mongoconn *mongo.Database, collection string, tanggapandata Tanggapan) interface{} {
	filter := bson.M{"nik": tanggapandata.Nik}
	return atdb.GetOneDoc[Report](mongoconn, collection, filter)
}

func GetAllTanggapanID(mongoconn *mongo.Database, collection string, tanggapandata Tanggapan) Tanggapan {
	filter := bson.M{
		"nik":     		tanggapandata.Nik,
		"description": 	tanggapandata.Description,
		"daterespons": 	tanggapandata.DateRespons,
	}
	tanggapanID := atdb.GetOneDoc[Tanggapan](mongoconn, collection, filter)
	return tanggapanID
}
