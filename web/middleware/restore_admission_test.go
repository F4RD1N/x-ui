package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/robfig/cron/v3"
)

func awaitRestoreSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(description)
	}
}

func awaitMaintenanceFlag(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !database.Restoring() {
		if time.Now().After(deadline) {
			t.Fatal("restore did not close mutation admission")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRestoreAdmissionDrainsWriterAndRejectsNewRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RestoreAdmission())
	entered, releaseWriter, writerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	exclusive, releaseRestore, restoreDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var writerOnce, restoreOnce sync.Once
	unblockWriter := func() { writerOnce.Do(func() { close(releaseWriter) }) }
	unblockRestore := func() { restoreOnce.Do(func() { close(releaseRestore) }) }
	defer unblockWriter()
	defer unblockRestore()
	var writes atomic.Int32
	router.POST("/prefix/panel/api/inbounds/add", func(c *gin.Context) {
		if writes.Add(1) == 1 {
			close(entered)
			<-releaseWriter
		}
		c.Status(http.StatusCreated)
	})
	router.GET("/prefix/status", func(c *gin.Context) { c.Status(http.StatusOK) })
	go func() {
		defer close(writerDone)
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/prefix/panel/api/inbounds/add", nil))
	}()
	awaitRestoreSignal(t, entered, "writer not admitted")
	go func() {
		defer close(restoreDone)
		release := database.BeginRestore()
		defer release()
		close(exclusive)
		<-releaseRestore
	}()
	awaitMaintenanceFlag(t)
	select {
	case <-exclusive:
		t.Fatal("restore acquired exclusive access before the admitted writer drained")
	default:
	}
	for _, request := range []struct{ method, path string }{{http.MethodPost, "/prefix/panel/api/inbounds/add"}, {http.MethodGet, "/prefix/status"}} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(request.method, request.path, nil))
		if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
			t.Fatalf("request during restore was not rejected: %s %d", request.method, recorder.Code)
		}
	}
	if writes.Load() != 1 {
		t.Fatal("a new mutation ran during restore")
	}
	unblockWriter()
	awaitRestoreSignal(t, writerDone, "admitted writer did not finish")
	awaitRestoreSignal(t, exclusive, "restore failed to acquire exclusive access after writer drained")
	unblockRestore()
	awaitRestoreSignal(t, restoreDone, "restore did not release admission")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/prefix/panel/api/inbounds/add", nil))
	if recorder.Code != http.StatusCreated || writes.Load() != 2 {
		t.Fatal("normal mutation behavior was not restored")
	}
}

func TestRestoreImportRouteBypassesMutationLockWithCustomBasePath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RestoreAdmission())
	router.POST("/custom/panel/api/server/importDB", func(c *gin.Context) {
		release := database.BeginRestore()
		defer release()
		c.Status(http.StatusAccepted)
	})
	done := make(chan struct{})
	recorder := httptest.NewRecorder()
	go func() {
		defer close(done)
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/custom/panel/api/server/importDB", nil))
	}()
	awaitRestoreSignal(t, done, "import route deadlocked by acquiring restore while holding mutation admission")
	if recorder.Code != http.StatusAccepted || database.Restoring() {
		t.Fatalf("import request failed or leaked maintenance state: %d", recorder.Code)
	}
}

func TestRestoreImportRefusesActiveLifecycleBeforeReadingBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RestoreAdmission())
	called := false
	router.POST("/custom/panel/api/server/importDB", func(c *gin.Context) {
		called = true
		c.Status(http.StatusAccepted)
	})
	release, ok := database.TryLifecycle()
	if !ok {
		t.Fatal("lifecycle admission failed")
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/custom/panel/api/server/importDB", nil))
	release()
	if recorder.Code != http.StatusServiceUnavailable || called || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("import entered during lifecycle: status %d, called %v", recorder.Code, called)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/custom/panel/api/server/importDB", nil))
	if recorder.Code != http.StatusAccepted || !called {
		t.Fatal("import did not become available after lifecycle")
	}
}

func TestRestoreCronAdmissionDrainsActiveJobAndSkipsNewTicks(t *testing.T) {
	entered, releaseJob, jobDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	exclusive, releaseRestore, restoreDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var jobOnce, restoreOnce sync.Once
	unblockJob := func() { jobOnce.Do(func() { close(releaseJob) }) }
	unblockRestore := func() { restoreOnce.Do(func() { close(releaseRestore) }) }
	defer unblockJob()
	defer unblockRestore()
	wrapped := RestoreJobAdmission(cron.FuncJob(func() { close(entered); <-releaseJob }))
	go func() { defer close(jobDone); wrapped.Run() }()
	awaitRestoreSignal(t, entered, "cron job did not start")
	go func() {
		defer close(restoreDone)
		release := database.BeginRestore()
		defer release()
		close(exclusive)
		<-releaseRestore
	}()
	awaitMaintenanceFlag(t)
	var ticks atomic.Int32
	next := RestoreJobAdmission(cron.FuncJob(func() { ticks.Add(1) }))
	next.Run()
	if ticks.Load() != 0 {
		t.Fatal("new cron tick ran during restore")
	}
	select {
	case <-exclusive:
		t.Fatal("restore did not wait for the active cron job")
	default:
	}
	unblockJob()
	awaitRestoreSignal(t, jobDone, "cron job did not finish")
	awaitRestoreSignal(t, exclusive, "restore did not proceed after cron drain")
	unblockRestore()
	awaitRestoreSignal(t, restoreDone, "restore did not complete")
	next.Run()
	if ticks.Load() != 1 {
		t.Fatal("cron job did not resume after restore")
	}
}

func TestRestoreCronAdmissionReleasesAfterPanic(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Error("fixture job did not panic")
			}
		}()
		RestoreJobAdmission(cron.FuncJob(func() { panic("fixture") })).Run()
	}()
	done := make(chan struct{})
	go func() { release := database.BeginRestore(); release(); close(done) }()
	awaitRestoreSignal(t, done, "panic leaked mutation admission")
}

func TestRestoreHTTPAdmissionReleasesAfterRecoveredPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.CustomRecovery(func(c *gin.Context, _ any) { c.AbortWithStatus(http.StatusInternalServerError) }))
	router.Use(RestoreAdmission())
	router.POST("/mutate", func(*gin.Context) { panic("fixture") })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mutate", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected panic response %d", recorder.Code)
	}
	done := make(chan struct{})
	go func() { release := database.BeginRestore(); release(); close(done) }()
	awaitRestoreSignal(t, done, "HTTP panic leaked mutation admission")
}
