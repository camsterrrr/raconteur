FROM ubuntu:latest

LABEL version="0.1"
LABEL description="Build Environment for Raconteur Source Code"
ENV LANG=en_US.utf8

RUN mkdir /raconteur

WORKDIR /raconteur

RUN apt update && apt install -y git python3 python3-pip python3-venv
RUN python3 -m venv /tmp/.venv
