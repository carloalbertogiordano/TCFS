DESCRIPTION=${1}
EXECUTABLE_PATH=${2}
RESTART=${3}
WANTED_BY=${4}

# Generate the tcfs.service file
	echo "[Unit]"
	echo "Description=${DESCRIPTION}"
	echo ""
	echo "[Service]"
	echo "Type=forking"
	echo "ExecStart=+${EXECUTABLE_PATH}"
	echo "StandardOutput=file:/var/log/tcfs/log.txt"
  echo "OpenFile=/tmp/tcfs_queue"
	echo "#Restart=${RESTART}"
	echo ""
	echo "[Install]"
	echo "WantedBy=${WANTED_BY}"

