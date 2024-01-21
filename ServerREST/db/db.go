package DB

import (
	TCFSTypes "daemon/types"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

// Init initializes the MariaDB client with the specified options.
func Init(host string, port string, dbname string, username string, password string) error {
	var err error
	dbConnectionString := username + ":" + password + "@tcp(" + host + ":" + port + ")/" + dbname
	db, err = sql.Open("mysql", dbConnectionString)
	if err != nil {
		fmt.Printf("ERR: %v\n", err)
		return err
	}

	// Check if the connection is valid
	err = db.Ping()
	if err != nil {
		fmt.Printf("ERR: %v\n", err)
		return err
	}

	fmt.Println("DB initialized")
	return nil
}

// Close is a method to close the database connection
func Close() error {
	err := db.Close()
	if err != nil {
		fmt.Printf("ERR: %v", err)
		return err
	}
	return nil
}

// InsertRegisteredUser inserts a new registered user into the RegisteredUsers table.
func InsertRegisteredUser(username string, passwordHash string) error {
	_, err := db.Exec("INSERT INTO RegisteredUsers (username, password_hash) VALUES (?, ?)", username, passwordHash)
	if err != nil {
		fmt.Printf("ERR: %v", err)
		return err
	}
	return nil
}

// InsertLoggedUser inserts a new logged user into the LoggedUsers table.
func InsertLoggedUser(username string, publicKey string) error {
	_, err := db.Exec("INSERT INTO LoggedUsers (username, public_key) VALUES (?, ?)", username, publicKey)
	if err != nil {
		fmt.Printf("ERR: %v", err)
		return err
	}
	return nil
}

func DeleteLoggedUser(username string) error {
	_, err := db.Exec("DELETE FROM LoggedUsers WHERE username=?", username)
	if err != nil {
		fmt.Printf("ERR: %v", err)
		return err
	}
	return nil
}

func GetPasswordHash(username string) (string, error) {
	// Query to obtain password hash
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM RegisteredUsers WHERE username = ?", username).Scan(&passwordHash)
	if err != nil {
		fmt.Printf("ERR: %v", err)
		return "", err
	}

	return passwordHash, nil
}

// InsertSharedFile inserts a new shared file into the SharedFiles table.
func InsertSharedFile(username string, fileID int, keypart string) error {
	_, err := db.Exec("INSERT INTO SharedFiles (username, fileID, keypart) VALUES (?, ?, ?)",
		username, fileID, keypart)
	if err != nil {
		fmt.Printf("ERR: %v", err)
		return err
	}
	return nil
}

func GetNewFileID() (int, error) {
	var lastFileID int

	// Esegui la stored procedure GetLastFileID
	_, err := db.Exec("CALL GetLastFileID(@output);")
	if err != nil {
		return 0, fmt.Errorf("failed to execute GetLastFileID: %w", err)
	}

	// Recupera il valore di output
	err = db.QueryRow("SELECT @output").Scan(&lastFileID)
	if err != nil {
		return 0, fmt.Errorf("failed to get last file ID: %w", err)
	}

	// Esegui la stored procedure IncrementLastFileID
	_, err = db.Exec("CALL IncrementLastFileID();")
	if err != nil {
		return 0, fmt.Errorf("failed to increment last file ID: %w", err)
	}

	return lastFileID, nil
}

// InsertMultipleSharedFiles Saves the shared files described by a slice of SharedFile structs in the DB
func InsertMultipleSharedFiles(sharedFilesList []TCFSTypes.SharedFile) error {

	for _, sharedFile := range sharedFilesList {
		err := InsertSharedFile(sharedFile.User.Username, sharedFile.FileID, sharedFile.EncryptedShare)
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadUserInfoByName retrieves user information from the LoggedUsers table based on the provided username.
func LoadUserInfoByName(user *TCFSTypes.TCFSUser) error {
	// SQL query to retrieve information from LoggedUsers based on the username
	query := "SELECT username, public_key FROM LoggedUsers WHERE username = ?"

	// Execute the query
	row := db.QueryRow(query, user.Username)

	// Variables to store the query results
	var username string
	var publicKey string

	// Scan the results into the corresponding variable
	if err := row.Scan(&username, &publicKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user not found: %s", user.Username)
		}
		return err
	}

	// Update the TCFSUser object with the retrieved information
	user.PublicKey = publicKey

	return nil
}
