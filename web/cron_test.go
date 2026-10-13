package web

import (
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

// A panicking job is recovered: it must not end the panel.
func TestCronRecoversPanickingJob(t *testing.T) {
	c := newCron(time.Local)
	id, err := c.AddFunc("@every 1h", func() { panic("job failed") })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the panic escaped the job: %v", r)
		}
	}()
	c.Entry(id).WrappedJob.Run()
	var _ cron.Logger = cronLogger{}
}
