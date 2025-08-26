# Use an official Python runtime as a parent image
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \ 
	docker.io \
	python3 \ 
	python3-pip \
	curl \
	tree \
	wget \
	zip

RUN curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

COPY ./src /src
WORKDIR /src/agentlib
RUN pip3 install selenium
RUN pip3 install -e .
