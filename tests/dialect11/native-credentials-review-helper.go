//go:build ignore

// Executed explicitly by native-defaults-review-ui.js, never linked into the panel.
package main

import (
	"encoding/json"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"os"
)

func main() {
	var request service.NativeCredentialRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		panic(err)
	}
	var obj any
	var err error
	if request.Kind == "inbound-profile" {
		obj, err = service.GenerateNativeInboundProfile(request)
	} else if request.Kind == "openvpn-client" {
		obj, err = service.GenerateNativeOpenVPNClient(request)
	} else {
		obj, err = service.GenerateNativeCredentials(request)
	}
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"success": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "obj": obj})
}
