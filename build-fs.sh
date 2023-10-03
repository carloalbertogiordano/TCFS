#!/bin/bash

if [[ ! -d "build-fs" ]]; then
  echo "The build folder does not exist, creating..."
  mkdir -p build-fs
fi

# Verify if this is a clean build "clean"
if [[ $1 == "clean" ]]; then
  echo "Pulizia della cartella build-fs..."
  rm -r build-fs
  mkdir build-fs
fi

cd build-fs
echo "Executing CMake..."
cmake ../module

echo "Executing make..."
make

echo "Copying tcfs in bin..."
cp tcfs ../bin/tcfs

if [[ $1 == "install" ]]; then
  echo "Installing tcfs"
  sudo make install
fi
