package service

// addPanelPorts adds the panel's own web port, and the subscription port
// when that server is on, to the ports kept out of the ephemeral range. Both
// are outside the kernel's default range only by luck (the installer's 60000
// is inside it, and "x-ui tune" widens the range to 10000-65535): an
// outgoing connection holding one while the panel restarts would stop the
// panel from listening.
func (s *XrayService) addPanelPorts(ports map[int]bool) {
	if p, err := s.settingService.GetPort(); err == nil && p > 0 && p <= 65535 {
		ports[p] = true
	}
	if on, err := s.settingService.GetSubEnable(); err == nil && on {
		if p, err := s.settingService.GetSubPort(); err == nil && p > 0 && p <= 65535 {
			ports[p] = true
		}
	}
}
