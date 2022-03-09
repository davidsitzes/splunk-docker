#!/bin/bash

docker-compose kill;

docker container kill $(docker ps -q);
docker container rm $(docker ps -a -q);
docker system prune -f;
docker volume prune -f;
docker-compose up -d;