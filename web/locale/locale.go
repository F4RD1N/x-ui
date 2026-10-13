// Package locale provides internationalization (i18n) support for the 3x-ui web panel,
// including translation loading, localization, and middleware for web and bot interfaces.
package locale

import (
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
)

// Requests run at once in many languages, so nothing here is set per
// request: each request gets a localizer of its own in its context. The
// shared state below changes only when the translations are (re)loaded.
var (
	mu         sync.RWMutex
	i18nBundle *i18n.Bundle
	matcher    language.Matcher // picks a request's language among the bundle's
	// LocalizerWeb speaks the default language, for web text outside a request.
	LocalizerWeb *i18n.Localizer
	LocalizerBot *i18n.Localizer
)

// I18nType represents the type of interface for internationalization.
type I18nType string

const (
	Bot I18nType = "bot" // Bot interface type
	Web I18nType = "web" // Web interface type
)

// Context keys set by LocalizerMiddleware and Pages.
const (
	langTagKey = "lang_tag"
	pagesKey   = "locale_pages"
)

// SettingService interface defines methods for accessing locale settings.
type SettingService interface {
	GetTgLang() (string, error)
}

// InitLocalizer initializes the internationalization system with embedded translation files.
func InitLocalizer(i18nFS fs.FS, settingService SettingService) error {
	// set default bundle to English
	bundle := i18n.NewBundle(language.MustParse("en-US"))
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

	// parse files
	if err := parseTranslationFiles(i18nFS, bundle); err != nil {
		return err
	}

	// setup bot locale
	botLang, err := settingService.GetTgLang()
	if err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	setBundle(bundle)
	LocalizerBot = i18n.NewLocalizer(bundle, botLang)
	return nil
}

// setBundle makes b the bundle in use. mu must be held.
func setBundle(b *i18n.Bundle) {
	i18nBundle = b
	matcher = language.NewMatcher(b.LanguageTags())
	LocalizerWeb = i18n.NewLocalizer(b)
}

// currentBundle returns the bundle in use and its matcher. A subscription
// server running without InitLocalizer loads the translations from disk.
func currentBundle() (*i18n.Bundle, language.Matcher) {
	mu.RLock()
	b, m := i18nBundle, matcher
	mu.RUnlock()
	if b != nil {
		return b, m
	}
	mu.Lock()
	defer mu.Unlock()
	if i18nBundle == nil {
		b := i18n.NewBundle(language.MustParse("en-US"))
		b.RegisterUnmarshalFunc("toml", toml.Unmarshal)
		if err := loadTranslationsFromDisk(b); err != nil {
			logger.Warning("i18n lazy load failed:", err)
		}
		setBundle(b)
	}
	return i18nBundle, matcher
}

// createTemplateData creates a template data map from parameters with optional separator.
func createTemplateData(params []string, separator ...string) map[string]any {
	var sep string = "=="
	if len(separator) > 0 {
		sep = separator[0]
	}

	templateData := make(map[string]any)
	for _, param := range params {
		parts := strings.SplitN(param, sep, 2)
		templateData[parts[0]] = parts[1]
	}

	return templateData
}

// I18n retrieves a localized message for the given key and type.
// It supports both bot and web contexts, with optional template parameters.
// Returns the localized message or an empty string if localization fails.
// Web messages come in the default language; a request's own language is
// in the I18n function its context carries.
func I18n(i18nType I18nType, key string, params ...string) string {
	var localizer *i18n.Localizer

	mu.RLock()
	switch i18nType {
	case "bot":
		localizer = LocalizerBot
	case "web":
		localizer = LocalizerWeb
	default:
		mu.RUnlock()
		logger.Errorf("Invalid type for I18n: %s", i18nType)
		return ""
	}
	mu.RUnlock()

	return localize(localizer, key, params...)
}

// localize renders the message key with params through localizer.
func localize(localizer *i18n.Localizer, key string, params ...string) string {
	if localizer == nil {
		// Fallback to key if localizer not ready; prevents nil panic on pages like sub
		return key
	}

	msg, err := localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    key,
		TemplateData: createTemplateData(params),
	})
	if err != nil {
		logger.Errorf("Failed to localize message: %v", err)
		return ""
	}

	return msg
}

// LocalizerMiddleware returns a Gin middleware that sets up localization for web requests.
// It determines the user's language from cookies or Accept-Language header,
// creates a localizer instance, and stores it in the Gin context for use in handlers.
// Also provides the I18n function in the context; pages rendered with HTML
// use the same language.
func LocalizerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		bundle, m := currentBundle()
		var lang string

		if cookie, err := c.Request.Cookie("lang"); err == nil {
			lang = cookie.Value
		} else {
			lang = c.GetHeader("Accept-Language")
		}

		// The same choice go-i18n makes for lang, as one of the bundle's
		// languages: pages are kept per language, so the set must be finite.
		tags, _, _ := language.ParseAcceptLanguage(lang)
		_, i, _ := m.Match(tags...)
		tag := bundle.LanguageTags()[i]
		localizer := i18n.NewLocalizer(bundle, tag.String())

		c.Set("localizer", localizer)
		c.Set(langTagKey, tag)
		c.Set("I18n", func(i18nType I18nType, key string, keyParams ...string) string {
			if i18nType == Web {
				return localize(localizer, key, keyParams...)
			}
			return I18n(i18nType, key, keyParams...)
		})
		c.Next()
	}
}

// Pages renders an engine's html templates in the language of each request.
// {{ i18n }} cannot be handed the request, so every language gets a copy of
// the templates whose i18n speaks it. The copies are made from a parsed set
// that is never executed, because html/template cannot copy a set once it
// has run.
type Pages struct {
	master *template.Template
	load   func() (*template.Template, error)
	mu     sync.Mutex
	byTag  map[language.Tag]*template.Template
}

// NewPages returns Pages copying master, a parsed set with an "i18n"
// function, for each language.
func NewPages(master *template.Template) *Pages {
	return &Pages{master: master, byTag: map[language.Tag]*template.Template{}}
}

// NewDiskPages returns Pages that parse the templates with load for every
// page, so edits show without a restart (debug mode).
func NewDiskPages(load func() (*template.Template, error)) *Pages {
	return &Pages{load: load}
}

// Middleware has the requests it handles render their pages with p.
func (p *Pages) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(pagesKey, p)
	}
}

// forTag returns the templates for the language tag, whose i18n localizes
// with localizer.
func (p *Pages) forTag(tag language.Tag, localizer *i18n.Localizer) (*template.Template, error) {
	funcs := template.FuncMap{
		"i18n": func(key string, params ...string) string {
			return localize(localizer, key, params...)
		},
	}
	if p.load != nil {
		t, err := p.load()
		if err != nil {
			return nil, err
		}
		return t.Funcs(funcs), nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.byTag[tag]; ok {
		return t, nil
	}
	t, err := p.master.Clone()
	if err != nil {
		return nil, err
	}
	t.Funcs(funcs)
	p.byTag[tag] = t
	return t, nil
}

// HTML renders the template name with data in the language of the request.
func HTML(c *gin.Context, code int, name string, data any) {
	p, _ := c.Value(pagesKey).(*Pages)
	if p == nil {
		c.HTML(code, name, data)
		return
	}
	tag, ok := c.Value(langTagKey).(language.Tag)
	localizer, _ := c.Value("localizer").(*i18n.Localizer)
	if !ok || localizer == nil {
		bundle, _ := currentBundle()
		tag = bundle.LanguageTags()[0]
		localizer = i18n.NewLocalizer(bundle)
	}
	t, err := p.forTag(tag, localizer)
	if err != nil {
		logger.Error("rendering", name, "failed:", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Render(code, render.HTML{Template: t, Name: name, Data: data})
}

// loadTranslationsFromDisk attempts to load translation files from "web/translation" using the local filesystem.
func loadTranslationsFromDisk(bundle *i18n.Bundle) error {
	root := os.DirFS("web")
	return fs.WalkDir(root, "translation", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(root, path)
		if err != nil {
			return err
		}
		_, err = bundle.ParseMessageFileBytes(data, path)
		return err
	})
}

// parseTranslationFiles parses embedded translation files and adds them to the i18n bundle.
func parseTranslationFiles(i18nFS fs.FS, i18nBundle *i18n.Bundle) error {
	err := fs.WalkDir(i18nFS, "translation",
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			data, err := fs.ReadFile(i18nFS, path)
			if err != nil {
				return err
			}

			_, err = i18nBundle.ParseMessageFileBytes(data, path)
			return err
		})
	if err != nil {
		return err
	}

	return nil
}
