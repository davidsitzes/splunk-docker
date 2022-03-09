#!/bin/bash

./docker-splunk-clean.sh
./docker-splunk-install-network.sh;
./docker-splunk-install-so1.sh
./docker-splunk-install-uf1.sh;
