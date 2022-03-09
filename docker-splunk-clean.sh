docker container kill $(docker ps -q);
docker container rm $(docker ps -a -q) -f;
docker system prune -f;
docker volume prune -f;
