package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/robfig/cron/v3"
)

// RestoreAdmission drains admitted writes before database publication. The
// import handler owns the exclusive restore barrier itself and must never hold
// a mutation admission while acquiring it.
func RestoreAdmission() gin.HandlerFunc {
	return func(c *gin.Context) {
		unavailable := func() {
			c.Header("Cache-Control", "no-store")
			c.Header("Retry-After", "3")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"success": false,
				"msg":     "Panel restore is in progress. Retry shortly.",
				"code":    "RESTORE_IN_PROGRESS",
			})
		}
		if database.Restoring() {
			unavailable()
			return
		}
		method := c.Request.Method
		if method == http.MethodPost && strings.HasSuffix(c.FullPath(), "/server/importDB") {
			if database.LifecycleActive() {
				c.Header("Cache-Control", "no-store")
				c.Header("Retry-After", "3")
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"success": false,
					"msg":     "Panel reload is in progress. Retry shortly.",
					"code":    "PANEL_RELOAD_IN_PROGRESS",
				})
				return
			}
			c.Next()
			return
		}
		mutating := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
		// This legacy GET route creates a backup and sends it to bot admins.
		mutating = mutating || strings.HasSuffix(c.FullPath(), "/api/backuptotgbot")
		if !mutating {
			c.Next()
			return
		}
		release, ok := database.TryMutation()
		if !ok {
			unavailable()
			return
		}
		defer release()
		c.Next()
	}
}

// RestoreJobAdmission applies to all panel cron jobs, including jobs registered
// by controllers after startup. A job already running drains before restore;
// new ticks during maintenance are skipped rather than queued with stale state.
func RestoreJobAdmission(job cron.Job) cron.Job {
	return cron.FuncJob(func() {
		release, ok := database.TryMutation()
		if !ok {
			return
		}
		defer release()
		job.Run()
	})
}
