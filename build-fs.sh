#!/bin/bash

if [[ ! -d "build-fs" ]]; then
  echo "The build folder does not exist, creating..."
  mkdir -p build-fs
fi

if [[ $1 == "clean" ]]; then
  echo "Cleaning build-fs..."
  make clean
fi

if [[ $1 == "install" ]]; then
  echo "Installing tcfs"
  make
  sudo make install
fi

if [[ $1 == "make" ]]; then
  echo "Executing Make..."
  make all
fi

if [[ $1 == "clean-make" ]]; then
  echo "Cleaning..."
  make clean
  echo "Executing Make..."
  make all
fi

if [[ $1 == "help" ]]; then
  echo "This project is NOT complete"
  echo "Run ./build-fs to build the project"
  echo "Run ./build-fs clean to clean the build directory"
  echo "Run ./build-fs clean-make to clean and then make"
  echo "The compiled program is in the directory build-fs/"
fi


