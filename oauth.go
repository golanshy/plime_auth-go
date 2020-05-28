package plime_auth_go

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golanshy/plime_core-go/data_models/access_token_dto"
	"github.com/golanshy/plime_core-go/logger"
	"github.com/golanshy/plime_core-go/rest"
	"github.com/golanshy/plime_core-go/utils/rest_errors"
	"net/http"
	"os"
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
		Timeout:        5000 * time.Millisecond,
		ConnectTimeout: 5000 * time.Millisecond,
		BaseURL:        "",
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

func init() {
	oauthRestClient.BaseURL = os.Getenv("OAUTH_API_URL")
}

type oauthClient struct {
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

func AuthenticateRequest(request *http.Request) *rest_errors.RestErr {
	if request == nil {
		return nil
	}
	// Passing authorization in header Authorization Bearer abc123
	authorizationHeader := request.Header.Get("Authorization")
	var accessTokenId string
	if strings.Contains(authorizationHeader, "Bearer") {
		accessTokenId = strings.Split(authorizationHeader, "Bearer")[1]
	}
	accessTokenId = strings.TrimSpace(accessTokenId)
	if accessTokenId == "" {
		logger.Error("unauthorized access, no Bearer access token", nil)
		return rest_errors.NewUnauthorizedError("unauthorized access")
	}
	// Call the OAuth API and validate it
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			logger.Error("unauthorized access, Bearer access token not found", nil)
			return rest_errors.NewUnauthorizedError("unauthorized access")
		}
		return err
	}

	if at.IsExpired() {
		logger.Error("error access token expired", nil)
		return rest_errors.NewUnauthorizedError("access token expired")
	}

	cleanRequest(request)
	request.Header.Add(headerXPClientId, fmt.Sprintf("%s", at.ClientId))
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

func getAccessToken(accessTokenId string) (*access_token_dto.AccessToken, *rest_errors.RestErr) {
	path := fmt.Sprintf("/oauth/access_token/%s", accessTokenId)
	response := oauthRestClient.Get(path)
	logger.Info(fmt.Sprintf("trying to get access token from %s%s", oauthRestClient.BaseURL, path))

	if response == nil || response.Response == nil {
		err := errors.New("unknown error")
		if response != nil {
			err = response.Err
		}
		logger.Error(fmt.Sprintf("invalid rest client response when trying to get access token %s", response.Err.Error()), err)
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to get access token", err)
	}
	if response.StatusCode > 299 {
		var restErr *rest_errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			logger.Error(fmt.Sprintf("invalid error interface when trying to get access token %s", response.Err.Error()), err)
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}
	var at access_token_dto.AccessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		logger.Error(fmt.Sprintf("error unmarshaling json response when trying to get access token %s", response.Err.Error()), err)
		return nil, rest_errors.NewInternalServerError("error unmarshaling json response when trying to get access token", err)
	}
	return &at, nil
}
