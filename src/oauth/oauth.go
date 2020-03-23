package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/golanshy/plime_core-go/src/utils/rest_errors"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic        = "X-Public"
	headerXPClientId     = "X-Client-Id"
	headerXPUserId       = "X-User-Id"
	parameterAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		Timeout:        500 * time.Millisecond,
		ConnectTimeout: 500 * time.Millisecond,
		BaseURL:        "http://127.0.0.1:8080",
		ContentType:    0,
		DisableCache:   false,
		DisableTimeout: false,
		FollowRedirect: false,
		CustomPool:     nil,
		BasicAuth:      nil,
		UserAgent:      "",
		Client:         nil,
	}
)

type oauthClient struct {
}

type accessToken struct {
	TokenType   string `json:"token_type,omitempty"`
	AccessToken string `json:"access_token"`
	UserId      int64  `json:"user_id,omitempty"`
	ClientId    string `json:"client_id,omitempty"`
	Expires     int64  `json:"expires"`
}

type oauthInterface interface {

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
	callerId, err := strconv.ParseInt(request.Header.Get(headerXPUserId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXPClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}
	// http://api.domain.com/resource?access_token=abc123
	//accessTokenId := strings.TrimSpace(request.URL.Query().Get(parameterAccessToken))

	// Passing authorization in header Authorization Bearer abc123
	authorizationHeader := c.GetHeader("Authorization")
	var accessTokenId string
	if strings.Contains(authorizationHeader, "Bearer") {
		accessTokenId = strings.Split(authorizationHeader, "Bearer")[1]
	}

	if accessTokenId == "" {
		return nil
	}

	// Call the OAuth API and validate it
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}

	cleanRequest(request)
	request.Header.Add(headerXPClientId, fmt.Sprintf("%d", at.ClientId))
	request.Header.Add(headerXPUserId, fmt.Sprintf("%d", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXPClientId)
	request.Header.Del(headerXPUserId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to get access token", nil)
	}
	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error unmarshaling json response when trying to get access token", err)
	}
	return &at, nil
}
