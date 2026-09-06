SHELL := /usr/bin/env bash

MODULE := github.com/gxbrave/AntiNAT-Agent
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
LDFLAGS := -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(DATE)

.PHONY: all test vet build cross-build check clean

all: check build

test:
	GOWORK=off go test ./...

vet:
	GOWORK=off go vet ./...

build:
	mkdir -p bin
	GOWORK=off go build -trimpath -ldflags "$(LDFLAGS)" -o bin/antinat-agent ./cmd/antinat-agent

cross-build:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOWORK=off go build ./cmd/antinat-agent

check: test vet

clean:
	go clean
