package edumasbackend

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "edumas"
	userdata.Password = "edumaspass"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin
	admindata.Username = "edumasmin"
	admindata.Password = "edumasmin1"
	admindata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	CreateNewAdminRole(mconn, "admin", admindata)
}	

func TestDeleteUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata User
	userdata.Username = "edumas"
	DeleteUser(mconn, "user", userdata)
}

//user
func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "edumas"
	userdata.Password = "edumaspass"
	userdata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "edumasdb")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

//admin
func CreateNewAdminToken(t *testing.T) {
	var admindata Admin
	admindata.Username = "edumasmin"
	admindata.Password = "edumasmin1"
	admindata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "edumasdb")

	// Call the function to create a admin and generate a token
	err := CreateAdminAndAddToken("your_private_key_env", mconn, "admin", admindata)

	if err != nil {
		t.Errorf("Error creating admin and token: %v", err)
	}
}

//user
func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata User
	userdata.Username = "edumas"
	userdata.Password = "edumaspass"
	userdata.Role = "user"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestGFCPostHandlerUserNew(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata UserNew
	userdata.Username = "balusername"
	userdata.Password = "balpassword"
	userdata.Role = "user"
	userdata.Notelp = "08113232132"
	CreateNewUserRoleNew(mconn, "user", userdata)
}

//admin
func TestGFCPostHandlerAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var admindata Admin
	admindata.Username = "edumasmin"
	admindata.Password = "edumasmin1"
	admindata.Role = "Admin"
	CreateNewAdminRole(mconn, "admin", admindata)
}

func TestReport(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var reportdata Report
	reportdata.No = 1
	reportdata.Nik = 121213
	reportdata.Nama = "ujang"
	reportdata.Title = "Jalan Rusak"
	reportdata.Description = "Di sarijadi ada jalan bolong rusak tepatnya di sariasih"
	reportdata.DateOccurred = "18-11-2024"
	reportdata.Image = "https://images3.alphacoders.com/165/thumb-1920-165265.jpg"
	CreateNewReport(mconn, "report", reportdata)
}

func TestTanggapan(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var tanggapandata Tanggapan
	tanggapandata.Nik = 12121
	tanggapandata.Description = "Baik akan segera kami proses"
	tanggapandata.DateRespons = "20-11-2024"
	CreateNewTanggapan(mconn, "tanggapan", tanggapandata)
}

func TestAllReport(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	report := GetAllReport(mconn, "report")
	fmt.Println(report)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "edumaspass"
	hash, _ := HashPass(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CompareHashPass(password, hash)
	fmt.Println("Match:   ", match)
}
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("edumaspass", privateKey)
	fmt.Println(hasil, err)
}

func TestGeneratePrivateKeyPasetoAdmin(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("adminpass", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata User
	userdata.Username = "edumasser"
	userdata.Password = "edumasser"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPass(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CompareHashPass(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)
}

func TestHashFunctionAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var admindata Admin
	admindata.Username = "admin123"
	admindata.Password = "admin321"

	filter := bson.M{"username": admindata.Username}
	res := atdb.GetOneDoc[Admin](mconn, "admin", filter)
	fmt.Println("Mongo Admin Result: ", res)
	hash, _ := HashPass(admindata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CompareHashPass(admindata.Password, res.Password)
	fmt.Println("Match:   ", match)
}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata User
	userdata.Username = "edumas"
	userdata.Password = "edumaspass"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestIsPasswordValidAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var admindata Admin
	admindata.Username = "edumasmin"
	admindata.Password = "edumasmin1"

	anu := IsPasswordValidAdmin(mconn, "admin", admindata)
	fmt.Println(anu)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata User
	userdata.Username = "edumasbal"
	userdata.Password = "edumasbal"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var admindata Admin
	admindata.Username = "edumasadmin"
	admindata.Password = "edumasadmin"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}

func TestLoginn(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var userdata User
	userdata.Username = "edumas"
	userdata.Password = "edumaspass"
	IsPasswordValid(mconn, "user", userdata)
	fmt.Println(userdata)
}

func TestLoginnNew(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasapk")
	var userdata2 User
	userdata2.Username = "edumas"
	userdata2.Password = "edumaspass"
	IsPasswordValid(mconn, "usernew", userdata2)
	fmt.Println(userdata2)
}

func TestLoginnAdmin(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "edumasdb")
	var admindata Admin
	admindata.Username = "edumasmin"
	admindata.Password = "edumasmin1"
	IsPasswordValidAdmin(mconn, "admin", admindata)
	fmt.Println(admindata)
}
