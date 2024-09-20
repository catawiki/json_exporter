VERSION 0.8

docker:
    ARG USERARCH
    FROM DOCKERFILE --build-arg ARCH=$USERARCH .
    ARG EARTHLY_GIT_SHORT_HASH
    ARG SHORT_SHA=$EARTHLY_GIT_SHORT_HASH
    ARG _IMAGE=json_exporter
    ARG TAG_NAME=latest

    SAVE IMAGE $_IMAGE:$SHORT_SHA
    SAVE IMAGE $_IMAGE:$TAG_NAME

tests:
    BUILD +docker
    FROM +docker
    RUN /usr/local/bin/json_exporter --help

all:
    BUILD +tests
