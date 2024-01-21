package REST_Functions

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	KeyTools "serverTCFS/crypt-utils"
	DB "serverTCFS/db"
	TCFSTypes "serverTCFS/types"
)

func deserializeUser(r *http.Request) (TCFSTypes.TCFSUser, error) {
	var user TCFSTypes.TCFSUser
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		return user, err
	}
	return user, nil
}

func Register(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Called Register")
	var user TCFSTypes.TCFSUser
	var err error = nil
	user, err = deserializeUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Insert the user into the RegisteredUsers table
	err = DB.InsertRegisteredUser(user.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("New user inserted \nSUCCESS\n")

	// Return a success message
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User registered successfully")
}

func Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Called Login\n")
	var user TCFSTypes.TCFSUser
	var err error = nil
	user, err = deserializeUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Retrieve the user's hashed password from the RegisteredUsers table
	hashedPassword, err := DB.GetPasswordHash(user.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Compare the user's password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	fmt.Println("Password match")

	// Insert the user into the LoggedUsers table
	err = DB.InsertLoggedUser(user.Username, user.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("Inserted in logged users")

	// Return a success message
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User logged in successfully")
}

func Logout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Called Unregister")
	var user TCFSTypes.TCFSUser
	var err error = nil
	user, err = deserializeUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = DB.DeleteLoggedUser(user.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	fmt.Printf("User %v unregistered\n SUCCESS\n", user.Username)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User logged out successfully")
}

/*
CreateSharedFile The request contains a username list and the k number for Shamir
A new key for the file will be generated and then Shamir generates all the key-parts
Each key-part is cyphered with the public key of the user and saved in the relative entry in the DB
A fileID is returned in the response. This will identify the file
*/
func CreateSharedFile(w http.ResponseWriter, r *http.Request) {

	type User struct {
		Username string `json:"username"`
	}

	type Request struct {
		Users []User `json:"users"`
		K     int    `json:"k"`
	}

	var req Request

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var users []TCFSTypes.TCFSUser
	for _, user := range req.Users {
		tmpUser := TCFSTypes.TCFSUser{Username: user.Username}
		err := DB.LoadUserInfoByName(&tmpUser)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			fmt.Printf("Could not load user %v info %v\n", user, err)
			return
		}
		users = append(users, tmpUser)
	}

	k := req.K

	fmt.Printf("Got users and k: %v\n", k)

	// Generate a new key
	key, err := KeyTools.GenerateKey()
	if err != nil {
		fmt.Printf("Err: cannot not generate new key %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Split the key using Shamir's secret sharing
	shares, err := KeyTools.SplitKey(key, len(users), k)
	if err != nil {
		fmt.Printf("Cannot split the key %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Got %v keyparts for %v users\n", len(shares), len(users))

	fileID, err := DB.GetNewFileID()
	if err != nil {
		fmt.Printf("Cannot generate a new fileID %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Got new file id %v\n", fileID)

	var sharedFilesList []TCFSTypes.SharedFile
	// Couple the shares with the user in the sharedFilesList
	j := 0
	for _, share := range shares {
		if share == nil {
			fmt.Printf("This share is nil\n")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sharedFile := TCFSTypes.SharedFile{
			User:           users[j],
			FileID:         fileID,
			Share:          share,
			EncryptedShare: "",
		}
		sharedFilesList = append(sharedFilesList, sharedFile)
		j++
	}
	fmt.Printf("Created %v shared files \n", len(sharedFilesList))

	for _, s := range sharedFilesList {
		fmt.Printf("%v\n", s)
	}

	err = KeyTools.EncryptSharesForSharedFileList(&sharedFilesList)
	if err != nil {
		fmt.Printf("Err: cannot Encrypt share list: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = DB.InsertMultipleSharedFiles(sharedFilesList)
	if err != nil {
		fmt.Printf("Err: cannot save list in DB  %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("New share saved to DB\n")

	// Return a success message
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, fmt.Sprintf("fileID:%v\n", fileID))
	fmt.Fprintf(w, "Shared file created successfully")
}
