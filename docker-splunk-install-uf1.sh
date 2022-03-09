#!/bin/bash

docker pull splunk/universalforwarder:latest;

###### UF1 #####

docker run -d --network skynet --name uf1 --hostname uf1 \
              -e "SPLUNK_PASSWORD=cdRN229s" \
              -e "SPLUNK_START_ARGS=--accept-license" \
              -e "SPLUNK_STANDALONE_URL=so1" \
              -it splunk/universalforwarder:latest;
docker exec -it uf1 sudo microdnf install yum;
docker exec -it uf1 sudo yum install nano -y;

#### START UP DOCKER CONTAINER ####
_status=`docker inspect -f {{.State.Health.Status}} uf1`
 printf "\rDocker Container Status: ${_status} "
while [ "`docker inspect -f {{.State.Health.Status}} uf1`" != "healthy" ]; do
     printf "."
     sleep 1;
done
_status=`docker inspect -f {{.State.Health.Status}} uf1`
printf "\r\nDocker Container Status: ${_status}"
echo " ";
