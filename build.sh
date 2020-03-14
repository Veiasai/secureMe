#!/bin/bash

if [[ ! -d "build" ]]
then 
    mkdir build
    mkdir build/debug
    mkdir build/release
fi

cmake -DCMAKE_BUILD_TYPE=Debug -S . -B build/debug

cmake -DCMAKE_BUILD_TYPE=Release -S . -B build/release
