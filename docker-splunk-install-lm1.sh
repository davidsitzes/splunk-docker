#!/bin/bash

function ProgressBar {
# Process data
    let _progress=(${1}*100/${2}*100)/100
    let _done=(${_progress}*4)/10
    let _left=40-$_done
# Build progressbar string lengths
    _fill=$(printf "%${_done}s")
    _empty=$(printf "%${_left}s")

# 1.2 Build progressbar strings and print the ProgressBar line
# 1.2.1 Output example:                           
# 1.2.1.1 Progress : [########################################] 100%
printf "\rProgress : [${_fill// /#}${_empty// /-}] ${_progress}%%"

}

docker pull splunk/splunk:latest;

##### STANDALONE #####
docker run -d --network skynet --name so1 --hostname so1 -p 8000:8000 \
              -e "SPLUNK_PASSWORD=cdRN229s" \
              -e "SPLUNK_START_ARGS=--accept-license" \
              -it splunk/splunk:latest;
docker exec -it so1 sudo microdnf install yum;
docker exec -it so1 sudo yum install nano -y;

echo "Waiting on so1 startup...";
_start=1
_end=45

while [ "`docker inspect -f {{.State.Health.Status}} so1`" != "healthy" ]; do
     _start=$((_start+1));
     if [ $_start -lt $_end ]
     then  
	ProgressBar ${_start} ${_end}
     else 
	ProgressBar ${_end} ${_end}
     fi;
     sleep 1; 
done
echo " ";

docker cp ~/OneDrive - TekStream Solutions/Docker/file_sharing/Splunk-NFR-ENT-50GB-2022-05-05.lic so1:/tmp/;
docker exec -it so1 sudo -i chmod 755 /tmp/Splunk-NFR-ENT-50GB-2022-05-05.lic;
docker exec -it so1 sudo -i chown -R splunk:splunk /tmp/Splunk-NFR-ENT-50GB-2022-05-05.lic;
docker exec -it so1 sudo -i mv /tmp/Splunk-NFR-ENT-50GB-2022-05-05.lic /opt/splunk/etc/licenses/;
docker exec -it so1 sudo -u splunk /opt/splunk/bin/splunk add licenses /opt/splunk/etc/licenses/Splunk-NFR-ENT-50GB-2022-05-05.lic -auth admin:cdRN229s;
docker exec -it so1 sudo -u splunk /opt/splunk/bin/splunk restart;
