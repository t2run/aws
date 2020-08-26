package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayCustomAuthorizerResponse, error) {

	fmt.Printf("Processing request data for request %s.\n", request.RequestContext.RequestID)
	fmt.Printf("Body size = %d.\n", len(request.Body))
	fmt.Println("Context")
	fmt.Println(ctx)
	fmt.Println("REQ")
	fmt.Println(request)
	uberSign := ""
	for key, value := range request.Headers {

		if key == "X-Uber-Signature" {
			uberSign = value
		}
		fmt.Printf("    %s: %s\n", key, value)
	}

	secret := getSecret()

	// if errSecret != nil {

	// }
	fmt.Println(" Secret is : " + secret)
	//data := "data"
	data := request.Body
	fmt.Printf("Secret: %s Data: %s\n", secret, data)

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	fmt.Println("Calculated Signature: " + sha)

	//respString := "Hello " + request.Body
	//fmt.Printf("Returning string: %v", respString)

	if sha == uberSign {
		return generatePolicy(map[string]interface{}{"name": secret}), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}
}

func getSecret() (secretString string) {
	secretName := "test/secret/lambda"
	region := "us-east-2"

	//Create a Secrets Manager client
	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
	// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	//var decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
	}
	return
}

func generatePolicy(context map[string]interface{}) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{}
	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   "Allow",
				Resource: []string{"*"},
			},
		},
	}

	authResponse.Context = context
	return authResponse
}
