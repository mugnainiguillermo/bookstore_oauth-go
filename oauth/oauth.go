package oauth

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/mugnainiguillermo/bookstore_utils-go/rest_errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic        = "X-Public"
	headerXClientId      = "X-Client-Id"
	headerXCallerId      = "X-Caller-Id"
	parameterAccessToken = "access_token"
)

var (
	client *resty.Client
)

func init() {
	client = resty.New().
		SetBaseURL("http://localhost:9001"). //oauth host
		SetTimeout(30 * time.Second)
}

type accessToken struct {
	Id      string `json:"access_token"`
	UserId  int64  `json:"user_id"`
	Expires int64  `json:"expires"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(parameterAccessToken))
	if accessTokenId == "" {
		return rest_errors.NewUnauthorizedError("invalid access token")
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}

	//request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	var at accessToken
	var restErr rest_errors.RestErr

	resp, err := client.R().
		SetResult(&at).
		SetError(&restErr).
		Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if err != nil {
		//TODO: Log properly
		return nil, rest_errors.NewInternalServerError("error during client request", nil)
	}

	if resp.IsError() {
		return nil, restErr
	}

	return &at, nil
}
