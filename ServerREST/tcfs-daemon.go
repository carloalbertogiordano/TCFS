package main

/**
 * @file main.go
 * @brief Main file for the TCFS server.
 */

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	DB "serverTCFS/db"
	restfunctions "serverTCFS/serverTools"
)

/**
 * @struct serverConfig
 * @brief Configuration structure for the server.
 */
type serverConfig struct {
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"Server"`
	DB struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		DBname   string `yaml:"dbname"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"db"`
}

/**
 * @brief Main function to start the TCFS server.
 */
func main() {
	// Parse command-line flags for the Server port
	var configFile string
	flag.StringVar(&configFile, "config-file", "config.yaml", "The location of the rest server config file")
	flag.Parse()

	// Read the YAML file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the YAML data into a Config struct
	var config serverConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new log file
	file, err := os.OpenFile("/tmp/tcfs-daemon.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Create a multi-writer that writes to both stdout and the log file
	multiWriter := io.MultiWriter(os.Stdout, file)

	// Set the logger to write to the multi-writer
	logger := log.New(multiWriter, "", log.LstdFlags)

	err = DB.Init(config.DB.Host, config.DB.Port, config.DB.DBname, config.DB.Username, config.DB.Password)
	if err != nil {
		fmt.Printf("Err initializing the DB: %v", err)
		return
	}
	http.HandleFunc("/register", restfunctions.Register)
	http.HandleFunc("/login", restfunctions.Login)
	http.HandleFunc("/logout", restfunctions.Logout)
	http.HandleFunc("/createSharedFile", restfunctions.CreateSharedFile)
	fmt.Printf("serving on %v\n", config.Server.Port)
	log.Fatal(http.ListenAndServe(":"+config.Server.Port, nil))

	// Terminate the program
	logger.Println("Server is exiting")
}
