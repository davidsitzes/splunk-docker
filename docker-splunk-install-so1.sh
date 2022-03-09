#!/bin/bash

#### GET LATEST #####
docker pull splunk/splunk:latest;

#### INSTALL NETWORK ####
docker run -d --network skynet --name so1 --hostname so1 -p 8000:8000 \
              -e "SPLUNK_PASSWORD=cdRN229s" \
              -e "SPLUNK_START_ARGS=--accept-license" \
              -it splunk/splunk:latest;

#### INSTALL ADD-ON FUNCTIONALITY #####
docker exec -it so1 sudo microdnf install yum;
docker exec -it so1 sudo yum install nano -y;

#### START UP DOCKER CONTAINER ####
_status=`docker inspect -f {{.State.Health.Status}} so1`
 printf "\rDocker Container Status: ${_status} "
while [ "`docker inspect -f {{.State.Health.Status}} so1`" != "healthy" ]; do
     printf "."
     sleep 1; 
done
_status=`docker inspect -f {{.State.Health.Status}} so1`
printf "\r\nDocker Container Status: ${_status}"
echo " ";

#### INSTALL ITSI APP ####
#docker cp file_sharing/splunk-it-service-intelligence_312.spl so1:/tmp/;
#docker exec -it so1 sudo -i chmod 755 /tmp/splunk-it-service-intelligence_312.spl;
#docker exec -it so1 sudo -i chown -R splunk:splunk /tmp/splunk-it-service-intelligence_312.spl;

#docker exec -it so1 sudo mkdir /tmp/itsi;
#docker exec -it so1 sudo -i tar -pxvf /tmp/splunk-it-service-intelligence_312.spl -C /opt/splunk/etc/apps/;
#docker exec -it so1 sudo -i chmod 755 /opt/splunk/;
#docker exec -it so1 sudo -i chown -R splunk:splunk /opt/splunk/;

#### INSTALL LICENSE ####
docker cp file_sharing/Splunk-NFR-ENT-50GB-2022-05-05.lic so1:/tmp/;
docker exec -it so1 sudo -i chmod 755 /tmp/Splunk-NFR-ENT-50GB-2022-05-05.lic;
docker exec -it so1 sudo -i chown -R splunk:splunk /tmp/Splunk-NFR-ENT-50GB-2022-05-05.lic;
docker exec -it so1 sudo -i mv /tmp/Splunk-NFR-ENT-50GB-2022-05-05.lic /opt/splunk/etc/licenses/;
docker exec -it so1 sudo -u splunk /opt/splunk/bin/splunk add licenses /opt/splunk/etc/licenses/Splunk-NFR-ENT-50GB-2022-05-05.lic -auth admin:cdRN229s;

#### UPDATE APPS ####
#docker exec -it so1 sudo -u splunk /opt/splunk/bin/splunk install app python_upgrade_readines_app -update 1 -auth admin:cdRN229s;

#### RESTART SPLUNK ####
docker exec -it so1 sudo -u splunk /opt/splunk/bin/splunk restart;

#### START UP DOCKER CONTAINER ####
_status=`docker inspect -f {{.State.Health.Status}} so1`
 printf "\rDocker Container Status: ${_status} "
while [ "`docker inspect -f {{.State.Health.Status}} so1`" != "healthy" ]; do
     printf "."
     sleep 1; 
done
_status=`docker inspect -f {{.State.Health.Status}} so1`
printf "\r\nDocker Container Status: ${_status}"
echo " ";
