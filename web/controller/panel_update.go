package controller

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

// The optional dependency keeps route tests inert: they never launch an updater.
type panelUpdateBackend interface {
	StartPanelUpdate() (*service.PanelUpdateState, error)
	PanelUpdateStatus() (*service.PanelUpdateState, error)
}

func (a *ServerController) panelUpdateBackend() panelUpdateBackend {
	if a.panelUpdates != nil {
		return a.panelUpdates
	}
	return &a.serverService
}

// updatePanel returns acceptance and a job ID, not a completion notification.
func (a *ServerController) updatePanel(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	state, err := a.panelUpdateBackend().StartPanelUpdate()
	if err != nil {
		logger.Warning("Unable to start panel update: ", err)
		message := "unable to start the panel update; check update status or the server log"
		switch {
		case errors.Is(err, service.ErrPanelUpdateBusy):
			message = "a panel update is already running; wait for it to finish"
		case errors.Is(err, service.ErrPanelUpdateStartupTimeout):
			message = "updater startup could not be confirmed; check its status before trying again"
		}
		jsonObj(c, nil, errors.New(message))
		return
	}
	jsonObj(c, state, nil)
}

// panelUpdateStatus is registered in the same authenticated API group as POST.
func (a *ServerController) panelUpdateStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	state, err := a.panelUpdateBackend().PanelUpdateStatus()
	if err != nil {
		logger.Warning("Unable to read panel update status: ", err)
		jsonObj(c, nil, errors.New("panel update status is temporarily unavailable"))
		return
	}
	jsonObj(c, state, nil)
}
