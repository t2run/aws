
package main

import (
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	lambda.Start(handler)
}

func handler() {
	fmt.Println("Hello Lambda from Go")
}

//To build for linux
// $env:GOOS = "linux"
// $env:CGO_ENABLED = "0"
// $env:GOARCH = "amd64"
// go build -o main main.go
// ~\Go\Bin\build-lambda-zip.exe -output main.zip main
