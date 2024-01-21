package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestRegister(t *testing.T) {
	user := map[string]string{
		"username": "testUser",
		"password": "pass",
	}

	requestBody, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", "http://127.0.0.1:1234/register", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}

	// Esegui la richiesta HTTP
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	// Leggi il corpo della risposta
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Verifica che lo status code sia 200
	if response.StatusCode != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", response.StatusCode, http.StatusOK)
	}

	// Verifica che il messaggio di successo sia corretto
	expectedResponse := "User registered successfully"
	if string(body) != expectedResponse {
		t.Errorf("handler returned unexpected body: got %v want %v", string(body), expectedResponse)
	}

}

func TestLogin(t *testing.T) {
	// Crea una richiesta HTTP POST
	user := map[string]string{
		"username": "testUser",
		"password": "pass",
	}
	requestBody, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", "http://localhost:1234/login", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}

	// Esegui la richiesta HTTP
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	// Leggi il corpo della risposta
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Verifica che lo status code sia 200
	if response.StatusCode != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", response.StatusCode, http.StatusOK)
	}

	// Verifica che il messaggio di successo sia corretto
	expectedResponse := "User logged in successfully"
	if string(body) != expectedResponse {
		t.Errorf("handler returned unexpected body: got %v want %v", string(body), expectedResponse)
	}
}

func TestLogout(t *testing.T) {
	// Crea una richiesta HTTP POST
	user := map[string]string{
		"username": "testUser",
	}
	requestBody, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", "http://localhost:1234/logout", bytes.NewBuffer(requestBody))
	if err != nil {
		t.Fatal(err)
	}

	// Esegui la richiesta HTTP
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	// Leggi il corpo della risposta
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Verifica che lo status code sia 200
	if response.StatusCode != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", response.StatusCode, http.StatusOK)
	}

	// Verifica che il messaggio di successo sia corretto
	expectedResponse := "User logged out successfully"
	if string(body) != expectedResponse {
		t.Errorf("handler returned unexpected body: got %v want %v", string(body), expectedResponse)
	}
}

func TestShareFile(t *testing.T) {
	//register some users
	for i := 0; i < 10; i++ {
		user := map[string]string{
			"username": fmt.Sprintf("testUser%v", i),
			"password": "pass",
		}

		requestBody, err := json.Marshal(user)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest("POST", "http://127.0.0.1:1234/register", bytes.NewBuffer(requestBody))
		if err != nil {
			t.Fatal(err)
		}

		// Esegui la richiesta HTTP
		client := &http.Client{}
		_, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}

	}
	//Log in the users
	//register some users
	for i := 0; i < 10; i++ {
		user := map[string]string{
			"username":  fmt.Sprintf("testUser%v", i),
			"password":  "pass",
			"publickey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJy21YMY4pGMWRJwQvZe\n7gXIuvPS5JeCxXXn/6xCsC5aeHlojP+/nLd+f1339Vrz1hXOJO1hEjFLsO8ZQCWk\nMpSSrMjy/z1/dg0U58yN9h1yitHtmeXSdEmU/UdLeTN5ztoRKJYTF3cywG4Bo6u/\nMCCowctVGSMUXibhbEbRVdxzQMm9I3AgEV6gD5UBLiAyuEkD7sLD/nolnJKP9hvi\nvvPvw982G/Kbe+Prs0FlJ9zPw4b+eSt7cNRUW+sRWRoUsC9Yuu2Gqs/8P1p8EY+S\n+pfTa7kjIILGR/DnbDglr2WdYS2/5CMXTV0qKRMt0HFt+5eSF/Te4gsm3E2SvJKZ\nCQIDAQAB\n-----END PUBLIC KEY-----",
		}

		requestBody, err := json.Marshal(user)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest("POST", "http://127.0.0.1:1234/login", bytes.NewBuffer(requestBody))
		if err != nil {
			t.Fatal(err)
		}

		// Esegui la richiesta HTTP
		client := &http.Client{}
		_, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}

	}

	//Now share a file
	sharedFilesRequest := map[string]interface{}{
		"users": []map[string]string{
			{"username": "testUser0"},
			{"username": "testUser1"},
			{"username": "testUser2"},
			{"username": "testUser3"},
			{"username": "testUser4"},
			{"username": "testUser5"},
			{"username": "testUser6"},
			{"username": "testUser7"},
			{"username": "testUser8"},
			{"username": "testUser9"},
			// Aggiungi altri utenti qui se necessario
		},
		"k": 4,
	}

	requestBody, err := json.Marshal(sharedFilesRequest)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("POST", "http://localhost:1234/createSharedFile", bytes.NewBuffer(requestBody))

	// Esegui la richiesta HTTP
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	// Leggi il corpo della risposta
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Verifica che lo status code sia 200
	if response.StatusCode != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", response.StatusCode, http.StatusOK)
	}

	fmt.Printf("%v\n", string(body))

}
