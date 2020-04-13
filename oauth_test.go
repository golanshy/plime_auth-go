package plime_auth_go

import (
	"github.com/golanshy/plime_core-go/rest"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	rest.StartMockupServer()
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXPClientId)
	assert.EqualValues(t, "X-User-Id", headerXPUserId)
	assert.EqualValues(t, "access_token", parameterAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "")
	assert.True(t, IsPublic(&request))
}

func TestGetCallerIdNilRequest(t *testing.T) {

}

func TestGetCallerIdInvalidCaller(t *testing.T) {

}

func TestGetCallerIdNoError(t *testing.T) {

}

func TestAuthenticateRequest(t *testing.T) {

}

func TestGetAccessTokenInvalidRestClientResponse(t *testing.T) {
	//rest.FlushMockups()
	//rest.AddMockups(&rest.Mock{
	//	HTTPMethod:   http.MethodGet,
	//	URL:          "http://localhost:8080/oauth/access_token/Abc123",
	//	ReqBody:      ``,
	//	RespHttpCode: http.StatusNotFound,
	//	RespBody:     `{}`,
	//})
	//
	//accessToken, err = getAccessToken("Abc123")
	//assert.Nil(t, accessToken)
	//assert.NotNil(t, err)
	//assert.EqualValues(t, http.StatusInternalServerError, err.Status)
	//assert.EqualValues(t, "Invalid rest client...", err.Message)
}
