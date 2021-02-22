package plime_auth_go

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golanshy/plime_core-go/data_models/access_token_dto"
	"github.com/golanshy/plime_core-go/data_models/id_dto"
	"github.com/golanshy/plime_core-go/data_models/user_dto"
	"github.com/golanshy/plime_core-go/logger"
	"github.com/golanshy/plime_core-go/rest"
	"github.com/golanshy/plime_core-go/utils/crypto_utils"
	"github.com/golanshy/plime_core-go/utils/rest_errors"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

const (
	headerXPublic        = "X-Public"
	headerXPClientId     = "X-Client-Id"
	headerXPUserId       = "X-User-Id"
	headerXSessionId     = "X-Session-Id"
	headerXSessionLength = 24
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

	usersRestClient = rest.RequestBuilder{
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
	oauthRestClient.BaseURL = strings.TrimSpace(os.Getenv("OAUTH_API_URL"))
	if oauthRestClient.BaseURL == "" {
		panic(errors.New("missing OAUTH_API_URL"))
	}
	usersRestClient.BaseURL = strings.TrimSpace(os.Getenv("USERS_API_URL"))
	if usersRestClient.BaseURL == "" {
		panic(errors.New("missing USERS_API_URL"))
	}
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

func GetCallerId(request *http.Request) string {
	if request == nil {
		return ""
	}
	return request.Header.Get(headerXPUserId)
}

func GetClientId(request *http.Request) string {
	if request == nil {
		return ""
	}
	return request.Header.Get(headerXPClientId)
}

func AuthenticateBasicAuthRequest(request *http.Request) *rest_errors.RestErr {
	if request == nil {
		return nil
	}

	requestDump, _ := httputil.DumpRequest(request, true)
	if requestDump != nil {
		fmt.Println(string(requestDump))
		logger.Info(string(requestDump))
	}

	username, password, ok := request.BasicAuth()
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if !ok {
		logger.Error("unauthorized access, invalid basic auth params", nil)
		return rest_errors.NewUnauthorizedError("unauthorized access")
	}

	oauthRestClient.BasicAuth = &rest.BasicAuth{
		UserName: username,
		Password: password,
	}

	path := fmt.Sprintf("/oauth/basic_auth")
	response := oauthRestClient.Post(path, nil)
	logger.Info(fmt.Sprintf("trying to basic auth %s%s", oauthRestClient.BaseURL, path))

	if response == nil || response.Response == nil {
		err := errors.New("unknown error")
		if response != nil {
			err = response.Err
		}
		logger.Error(fmt.Sprintf("invalid rest client response when trying to basic auth %s", err.Error()), err)
		return rest_errors.NewInternalServerError("invalid rest client response when trying to basic auth", err)
	}
	if response.StatusCode > 299 {
		var restErr *rest_errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			logger.Error(fmt.Sprintf("invalid error interface when trying to basic auth %s", response.Err.Error()), err)
			return rest_errors.NewInternalServerError("invalid error interface when trying to basic auth", err)
		}
		return restErr
	}

	return nil
}

func AuthenticatePublicRequest(request *http.Request) *rest_errors.RestErr {
	return authenticateRequest(request, true)
}

func AuthenticateRequest(request *http.Request) *rest_errors.RestErr {
	return authenticateRequest(request, false)
}

func authenticateRequest(request *http.Request, isPublic bool) *rest_errors.RestErr {
	if request == nil {
		return nil
	}

	requestDump, _ := httputil.DumpRequest(request, true)
	if requestDump != nil {
		fmt.Println(string(requestDump))
		logger.Info(string(requestDump))
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
		err := rest_errors.NewUnauthorizedError("access token expired")
		logger.Error(err.Message, errors.New(err.Message))
		return err
	}

	if !isPublic {
		if !at.EmailVerified {
			err = rest_errors.NewRestError("Email verification required", http.StatusForbidden, "email_verification_required")
			logger.Error(err.Message, errors.New(err.Message))
			return err
		}

		if !at.MobileVerified {
			err := rest_errors.NewRestError("Mobile verification required", http.StatusForbidden, "mobile_verification_required")
			logger.Error(err.Message, errors.New(err.Message))
			return err
		}
	}

	request.Header.Del(headerXPClientId)
	request.Header.Del(headerXPUserId)
	request.Header.Add(headerXPClientId, at.ClientId)
	request.Header.Add(headerXPUserId, at.UserId)

	if request.Header.Get(headerXSessionId) == "" {
		request.Header.Add(headerXSessionId, crypto_utils.GenerateSecret(headerXSessionLength))
	}

	return nil
}

func getAccessToken(accessTokenId string) (*access_token_dto.AccessToken, *rest_errors.RestErr) {
	path := fmt.Sprintf("/oauth/access_token/%s", accessTokenId)
	response := oauthRestClient.Get(path)

	if response == nil || response.Response == nil {
		err := errors.New("unknown error")
		if response != nil {
			err = response.Err
		}
		logger.Error(fmt.Sprintf("invalid rest client response when trying to get access token %s", err.Error()), err)
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

func GetUserId(request *http.Request, email string) (*id_dto.Id, *rest_errors.RestErr) {
	if request == nil {
		return nil, rest_errors.NewUnauthorizedError("unauthorized access")
	}
	// Passing authorization in header Authorization Bearer abc123
	usersRestClient.Headers = make(map[string][]string)
	usersRestClient.Headers.Add("Authorization", request.Header.Get("Authorization"))
	path := fmt.Sprintf("/users?email=%s", email)
	response := usersRestClient.Get(path)
	logger.Info(fmt.Sprintf("trying to get user from %s%s", usersRestClient.BaseURL, path))

	if response == nil || response.Response == nil {
		err := errors.New("unknown error")
		if response != nil {
			err = response.Err
		}
		logger.Error(fmt.Sprintf("invalid rest client response when trying to get user %s", err.Error()), err)
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to get user", err)
	}
	if response.StatusCode > 299 {
		var restErr *rest_errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			logger.Error(fmt.Sprintf("invalid error interface when trying to get user %s", response.Err.Error()), err)
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get user", err)
		}
		return nil, restErr
	}
	var user user_dto.User
	if err := json.Unmarshal(response.Bytes(), &user); err != nil {
		logger.Error(fmt.Sprintf("error unmarshaling json response when trying to get user %s", response.Err.Error()), err)
		return nil, rest_errors.NewInternalServerError("error unmarshaling json response when trying to get user", err)
	}

	return &id_dto.Id{
		Id: user.Id,
	}, nil
}
