package locale

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/mhsanaei/3x-ui/v2/logger"
)

type tgLang string

func (l tgLang) GetTgLang() (string, error) { return string(l), nil }

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "locale-test-log")
	if err != nil {
		panic(err)
	}
	os.Setenv("XUI_LOG_FOLDER", dir)
	logger.InitLogger(logging.CRITICAL)
	code := m.Run()
	logger.CloseLogger()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Requests in different languages at once each get their own: messages and
// pages alike (a shared localizer used to be swapped by every request).
func TestRequestsKeepTheirLanguage(t *testing.T) {
	if err := InitLocalizer(os.DirFS(".."), tgLang("en-US")); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(LocalizerMiddleware())
	master := template.Must(template.New("").Funcs(template.FuncMap{"i18n": func(string, ...string) string { return "" }}).
		Parse(`{{define "p.html"}}{{ i18n "pages.login.title" }}{{end}}`))
	engine.Use(NewPages(master).Middleware())
	engine.GET("/page", func(c *gin.Context) { HTML(c, http.StatusOK, "p.html", nil) })
	engine.GET("/msg", func(c *gin.Context) {
		f := c.MustGet("I18n").(func(I18nType, string, ...string) string)
		c.String(http.StatusOK, f(Web, "pages.login.title"))
	})

	want := map[string]string{"en-US": "Welcome", "fa-IR": "خوش\u200cآمدید"}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wrong, total := 0, 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				lang := "en-US"
				if (g+i)%2 == 1 {
					lang = "fa-IR"
				}
				for _, path := range []string{"/page", "/msg"} {
					r := httptest.NewRequest("GET", path, nil)
					r.AddCookie(&http.Cookie{Name: "lang", Value: lang})
					w := httptest.NewRecorder()
					engine.ServeHTTP(w, r)
					mu.Lock()
					total++
					if w.Body.String() != want[lang] {
						wrong++
					}
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()
	if wrong > 0 {
		t.Fatalf("%d of %d answers came in the other language", wrong, total)
	}

	// No cookie: the browser's language; an unknown one: English.
	for header, w := range map[string]string{"fa-IR,fa;q=0.9": "خوش\u200cآمدید", "xx-YY": "Welcome", "": "Welcome"} {
		r := httptest.NewRequest("GET", "/page", nil)
		r.Header.Set("Accept-Language", header)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, r)
		if rec.Body.String() != w {
			t.Errorf("Accept-Language %q: %q, want %q", header, rec.Body.String(), w)
		}
	}
}
