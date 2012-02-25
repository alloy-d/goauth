package oauth

import (
	"fmt"
	"os"
)

// Stores access token information to the given filename.
//
// Format is the same as the return from the server.
func (o *OAuth) Save(fileName string) (err error) {
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "oauth_token=%s&oauth_token_secret=%s", o.accessToken, o.accessSecret)
	if o.userId != 0 {
		fmt.Fprintf(file, "&user_id=%d", o.userId)
	}
	if o.userName != "" {
		fmt.Fprintf(file, "&screen_name=%s", o.userName)
	}

	return nil
}

// Loads access token information from a file.
func (o *OAuth) Load(fileName string) (err error) {
	file, err := os.Open(fileName)
	if err != nil {
		return
	}
	defer file.Close()

	return o.parseResponse(200, file, TokenReq)
}
