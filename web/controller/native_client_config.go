package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/util/native_client"
	"github.com/mhsanaei/3x-ui/v2/web/session"
)

// A token decoder rejects duplicate keys as well as unknown fields, null,
// arrays, and extra documents. Export never accepts client material from HTTP.
func nativeClientConfigEmail(body []byte) (string, error) {
	bad := errors.New("Expected one JSON object containing an email")
	if !utf8.Valid(body) {
		return "", bad
	}
	d := json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return "", bad
	}
	var email string
	found := false
	for d.More() {
		key, err := d.Token()
		if err != nil || key != "email" || found {
			return "", bad
		}
		if d.Decode(&email) != nil || email == "" {
			return "", bad
		}
		found = true
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || !found {
		return "", bad
	}
	if d.Decode(new(any)) != io.EOF {
		return "", bad
	}
	return email, nil
}

func (a *InboundController) nativeClientConfig(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	user := session.GetLoginUser(c)
	if user == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		jsonObj(c, nil, errors.New("Invalid inbound identity"))
		return
	}
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		jsonObj(c, nil, errors.New("Expected an application/json request"))
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
	if err != nil {
		jsonObj(c, nil, errors.New("Invalid client configuration request"))
		return
	}
	email, err := nativeClientConfigEmail(data)
	if err != nil {
		jsonObj(c, nil, err)
		return
	}
	host, err := native_client.RequestHost(c.Request.Host)
	if err != nil {
		jsonObj(c, nil, errors.New("A valid server endpoint is required"))
		return
	}
	result, err := a.inboundService.GetNativeClientConfig(user.Id, id, email, host)
	jsonObj(c, result, err)
}
