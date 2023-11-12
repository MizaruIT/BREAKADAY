## THE BREAKADAY IMAGE WITH DOCKER
**For breakaday, the images available are :**
- breakaday.all.dockerfile (X GB) = It contains everything (WiFi, wordlists, web pentest, AD pentest, basics tools, etc.)


## HOW IT WORKS
**I) GENERAL USAGE**
1) Build the image
```sh
# Go into the root directory of the Github project (where the README.md is)
docker build -f $DOCKERFILE_NAME . -t $TAG_NAME (you only need to replace $DOCKERFILE_NAME with the quoted images previously + write a tag_name)
```

2) Create a container with the image 
```sh
docker run -it -v $(pwd)/path_to_host_folder:/workspace --name persistent_$TAG_NAME $TAG_NAME
```

3) If the container is exited, you will need to re-start 
```sh
docker start $ID (you get the ID with docker container ls -a)
```

4) And then relaunch it
```sh
docker exec -it $ID zsh
```

**II) EXAMPLE (with breakaday.all.dockerfile)**
1) Build the image
```sh
# Go into the root directory of the Github project (where the README.md is)
docker build -f DOCKER/breakaday.all.dockerfile . -t breakaday_all (you only need to replace $DOCKERFILE_NAME with the quoted images previously + write a tag_name)
```

2) Create a container with the image 
```sh
docker run -it -v $(pwd)/PENTEST_ENTERPRISE/:/workspace --name persistent_breakaday_all_enterprise breakaday_all
```

3) If the container is exited, you will need to re-start 
```sh
docker start $ID (you get the ID with docker container ls -a)
```

4) And then relaunch it
```sh
docker exec -it $ID zsh
```

## COMMANDS - ALL IN ONE 
```sh
# Build and launch the breakaday image
docker build -f DOCKER/breakaday.all.dockerfile . -t breakaday_all
docker run -it -v $(pwd)/PENTEST/:/workspace --name persistent_breakaday_all_enterprise breakaday_all
docker container ls -a 
docker start $ID
docker exec -it $ID zsh
```

## BASICS DOCKER COMMANDS
1) Build an image
```sh
docker build -t $TAG_NAME -f $PATH_TO_DOCKERFILE . 
```

2) Run a container with an image (with folder mounted on host/container)
```sh
docker run -it -v $(pwd)/path_to_host_folder:/workspace --name $NAME $TAG_NAME (or ID)
=> $TAG_NAME = the name specified in step 1 (it can also be the ID)
=> $NAME = the name of the container that you will use when re-run it or anything else
```

3) Restart an exited container 
```sh
docker start $ID 
=> $ID, it can be retrieved with : docker container ls -a 
```

4) Re-run an exited container (after restarting it)
```sh
docker exec -it $ID zsh
```

## BONUS
```sh
# Remove all containers : docker rm -f $(docker ps -a -q)
# Remove all data unused : docker system prune
```
