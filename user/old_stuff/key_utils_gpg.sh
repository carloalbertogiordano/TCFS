#/**
# @file This file is temporary, it uses a bash script to execute gpg
# */

#!/bin/bash

dest_folder="$HOME/.tcfs"
recipient_mail=""

check_folder_exists() {
    local folder="$dest_folder"
    if [ -d "$folder" ]; then
        return 1
    else
        return 0
    fi
}

create_tcfs_folder() {
    local tcfs_folder="$dest_folder"

    if [ ! -d "$tcfs_folder" ]; then
        mkdir "$tcfs_folder"
        return 1
    else
        return 0
    fi
}

main() {
    check_folder_exists
    local folder_exists=$?
    if [ "$folder_exists" -eq 0 ]; then
        create_tcfs_folder
    fi
    #gpg --gen-key
    #encript key aes
    #openssl rand -hex 32 > "$dest_folder/"aes.key
    gpg --encrypt --recipient "$recipient_mail" "$dest_folder/"aes.key
    rm "$dest_folder/"aes.key

    #decrypt AES key
    gpg --decrypt "$dest_folder/"aes.key.gpg

    #done, lavoraci domani

    return 1
}

# Chiamata alla funzione principale
main


main