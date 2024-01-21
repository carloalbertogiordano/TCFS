package main

import (
	REST_Functions "daemon/daemonTools"
	DB "daemon/db"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type daemonConfig struct {
	Daemon struct {
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

func main() {
	// Parse command-line flags for the Server port
	var configFile string
	flag.StringVar(&configFile, "config-file", "/tmp/tcfsd.yaml", "The location of the rest server config file")
	flag.Parse()

	// Read the YAML file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the YAML data into a Config struct
	var config daemonConfig
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
	http.HandleFunc("/register", REST_Functions.Register)
	http.HandleFunc("/login", REST_Functions.Login)
	http.HandleFunc("/logout", REST_Functions.Logout)
	http.HandleFunc("/createSharedFile", REST_Functions.CreateSharedFile)
	fmt.Printf("serving on %v\n", config.Daemon.Port)
	log.Fatal(http.ListenAndServe(":"+config.Daemon.Port, nil))

	// Terminate the program
	logger.Println("Daemon is exiting")
}
