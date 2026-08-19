FROM python:3.12-slim

# Task 3's OS command injection payloads run through /ping, which shells out
# to the real `ping` binary — python:3.12-slim doesn't include it.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
