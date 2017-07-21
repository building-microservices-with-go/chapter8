packages:
	go get -u github.com/dvyukov/go-fuzz/go-fuzz
	go get -u github.com/dvyukov/go-fuzz/go-fuzz-build

build: packages
	go-fuzz-build github.com/building-microservices-with-go/chapter8/validation/fuzzer

run: build
	go-fuzz -bin=./fuzzer-fuzz.zip -workdir=output
