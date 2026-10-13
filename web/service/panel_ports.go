package service

import (
	"net"
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/util/common"
)

// The panel and its subscription server listen next to the cores. A port
// both want is lost by whichever binds last: a core backs off and retries
// for ever, and a server that cannot listen after the restart that applied
// a setting stays down. These checks keep them apart up front.

// panelPortUser names the panel's own server, "panel" or "subscription",
// that listens on port at an address overlapping listen, or returns "".
func panelPortUser(listen string, port int) string {
	var s SettingService
	overlaps := func(other string) bool {
		return wildcardListen(listen) || wildcardListen(other) || listen == other
	}
	if p, err := s.GetPort(); err == nil && p == port {
		if l, _ := s.GetListen(); overlaps(l) {
			return "panel"
		}
	}
	if on, _ := s.GetSubEnable(); on {
		if p, err := s.GetSubPort(); err == nil && p == port {
			if l, _ := s.GetSubListen(); overlaps(l) {
				return "subscription"
			}
		}
	}
	return ""
}

// checkServerPort refuses port for the panel's server what ("Web" or "Sub")
// when an inbound or a sub-inbound has it, or, when probe is set, when
// something on the host holds it now.
func checkServerPort(what, listen string, port int, probe bool) error {
	var inbounds InboundService
	if exist, err := inbounds.checkPortExist(listen, port, 0); err != nil {
		return err
	} else if exist {
		return common.NewErrorf("%s port %d is already used by an inbound", what, port)
	}
	if name, err := subPortUser(listen, port, 0); err != nil {
		return err
	} else if name != "" {
		return common.NewErrorf("%s port %d is already used by a sub-inbound of %s", what, port, name)
	}
	if !probe {
		return nil
	}
	l, err := net.Listen("tcp", net.JoinHostPort(listen, strconv.Itoa(port)))
	if err != nil {
		return common.NewErrorf("%s port %d cannot be used: %v", what, port, err)
	}
	l.Close()
	return nil
}

// holdsPort says whether a server listening on oldListen:oldPort holds
// listen:port itself: the same port at an overlapping address. A probe there
// fails on the server's own socket, so it cannot tell whether anything else
// holds the port; the inbound checks still apply.
func holdsPort(oldListen string, oldPort int, listen string, port int) bool {
	return port == oldPort && (wildcardListen(listen) || wildcardListen(oldListen) || listen == oldListen)
}

// checkServerPorts runs checkServerPort for the web and the subscription
// server when the address one of them would listen on changes; a server
// that keeps its address holds its port itself.
func (s *SettingService) checkServerPorts(webListen string, webPort int, subEnable bool, subListen string, subPort int) error {
	oldListen, _ := s.GetListen()
	oldPort, _ := s.GetPort()
	if webPort != oldPort || webListen != oldListen {
		if err := checkServerPort("Web", webListen, webPort, !holdsPort(oldListen, oldPort, webListen, webPort)); err != nil {
			return err
		}
	}
	if !subEnable {
		return nil
	}
	wasOn, _ := s.GetSubEnable()
	oldSubListen, _ := s.GetSubListen()
	oldSubPort, _ := s.GetSubPort()
	if wasOn && subPort == oldSubPort && subListen == oldSubListen {
		return nil
	}
	return checkServerPort("Sub", subListen, subPort, !(wasOn && holdsPort(oldSubListen, oldSubPort, subListen, subPort)))
}

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
