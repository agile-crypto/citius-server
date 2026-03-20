# docker pull postgres:latest
# Creates volume
docker volume create pgdata

POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=postgres
LOCAL_PORT=5432
CONTAINER_PORT=5432
NAME=gorm-tests
IMAGE=postgres

# Starts container
docker run -d \
  --name $NAME \
  --restart unless-stopped \
  -e POSTGRES_DB=$POSTGRES_DB \
  -e POSTGRES_USER=$POSTGRES_USER \
  -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
  -p $LOCAL_PORT:$CONTAINER_PORT \
  -v pgdata:/var/lib/postgresql \
  postgres

# Stop container
docker stop $NAME
# Remove container
docker rm $NAME
# Remove volume
docker volume rm pgdata