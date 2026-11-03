package controller

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

func (a *ServerController) nativeCredentials(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request service.NativeCredentialRequest
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		jsonMsg(c, "Invalid credential generation request", errors.New("expected one valid request object"))
		return
	}
	if request.Kind == "inbound-profile" {
		result, err := service.GenerateNativeInboundProfile(request)
		jsonObj(c, result, err)
		return
	}
	if request.Kind == "openvpn-client" {
		result, err := service.GenerateNativeOpenVPNClient(request)
		jsonObj(c, result, err)
		return
	}
	result, err := service.GenerateNativeCredentials(request)
	jsonObj(c, result, err)
}
