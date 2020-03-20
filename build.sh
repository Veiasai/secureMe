#!/bin/bash

if [[ ! -d "build" ]]
then 
    mkdir build
    mkdir build/debug
    mkdir build/release
fi

cd build/debug && cmake -DCMAKE_BUILD_TYPE=Debug ../..
cd ../release && cmake -DCMAKE_BUILD_TYPE=Release ../..