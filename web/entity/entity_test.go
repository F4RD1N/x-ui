package entity

import "testing"

// Paths the subscription server cannot route are refused when it is on.
func TestCheckValidSubPaths(t *testing.T) {
	base := func() *AllSetting {
		return &AllSetting{WebPort: 2053, SubPort: 2096, WebBasePath: "/", SubEnable: true,
			SubPath: "/sub/", SubJsonPath: "/json/", SubClashPath: "/clash/", SubJsonEnable: true, SubClashEnable: true}
	}
	if err := base().CheckValid(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, edit := range map[string]func(*AllSetting){
		"json = sub":     func(s *AllSetting) { s.SubJsonPath = "sub" },
		"clash = sub":    func(s *AllSetting) { s.SubClashPath = "/sub/" },
		"json = clash":   func(s *AllSetting) { s.SubClashPath = "/json/" },
		"sub in assets":  func(s *AllSetting) { s.SubPath = "/assets/" },
		"json in assets": func(s *AllSetting) { s.SubJsonPath = "/assets/x/" },
	} {
		s := base()
		edit(s)
		if err := s.CheckValid(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, edit := range map[string]func(*AllSetting){
		"json off":   func(s *AllSetting) { s.SubJsonEnable = false; s.SubJsonPath = "/sub/" },
		"clash off":  func(s *AllSetting) { s.SubClashEnable = false; s.SubClashPath = "/sub/" },
		"sub server": func(s *AllSetting) { s.SubEnable = false; s.SubPath = "/assets/" },
	} {
		s := base()
		edit(s)
		if err := s.CheckValid(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
