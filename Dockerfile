FROM node:24.12

LABEL org.opencontainers.image.description="Creates a environment to host the NodeJS and NPM environment."

USER root

RUN apt update -y && apt upgrade -y && apt install build-essential -y -q && \
  mkdir -p /app

WORKDIR /app