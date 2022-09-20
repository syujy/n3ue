BIN=bin/n3ue

.PHONY: all
all:
	go build -o ${BIN} n3ue.go

clean:
	rm -rf bin/
