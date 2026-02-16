#!/bin/bash
make clean
make debug
./emulate_payload.py
read -p "Press enter to continue"
make clean
make

