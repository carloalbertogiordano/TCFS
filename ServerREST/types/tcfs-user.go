package TCFSTypes

import "fmt"

type TCFSUser struct {
	Username  string
	Password  string
	PublicKey string
}

type SharedFile struct {
	User           TCFSUser
	FileID         int
	Share          []byte
	EncryptedShare string
}

func (s SharedFile) String() string {
	return fmt.Sprintf(""+
		"---------------------------------------------------------\n"+
		"User:\n"+
		"	Name%v\n"+
		"	Pubkey%v\n"+
		"	Pass%v\n"+
		"FileID: %v\n"+
		"Share: %v\n"+
		"EncryptedShare %v\n"+
		"---------------------------------------------------------"+
		"", s.User.Username, s.User.PublicKey, s.User.Password, s.FileID, s.Share, s.EncryptedShare)
}
