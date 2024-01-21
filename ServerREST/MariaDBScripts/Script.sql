DROP DATABASE IF EXISTS tcfs;
CREATE DATABASE IF NOT EXISTS tcfs;

USE tcfs;

CREATE TABLE IF NOT EXISTS RegisteredUsers (
    username VARCHAR(255) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS LoggedUsers (
    username VARCHAR(255),
    public_key VARCHAR(512) NOT NULL,
    PRIMARY KEY (username),
    FOREIGN KEY (username) REFERENCES RegisteredUsers(username)
);

CREATE TABLE IF NOT EXISTS SharedFiles (
    username VARCHAR(255),
    fileID INT,
    keypart VARCHAR(512) NOT NULL,
    PRIMARY KEY (username, fileID),
    FOREIGN KEY (username) REFERENCES RegisteredUsers(username)
);

CREATE TABLE IF NOT EXISTS Counter (
    lastFileID INT NOT NULL
);

INSERT INTO Counter (lastFileID) VALUES (1000);

DELIMITER //
CREATE PROCEDURE GetLastFileID(OUT lfID INT)
BEGIN
SELECT lastFileID INTO lfID FROM Counter LIMIT 1;
END //
DELIMITER ;

DELIMITER //
CREATE PROCEDURE IncrementLastFileID()
BEGIN
   UPDATE Counter SET lastFileID = lastFileID + 1;
END //
DELIMITER ;
