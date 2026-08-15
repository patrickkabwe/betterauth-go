package plugins

import (
	"sort"
	"strconv"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

// LocaleDetectionStrategy controls how the i18n plugin finds a request locale.
type LocaleDetectionStrategy string

const (
	LocaleFromHeader   LocaleDetectionStrategy = "header"
	LocaleFromCookie   LocaleDetectionStrategy = "cookie"
	LocaleFromSession  LocaleDetectionStrategy = "session"
	LocaleFromCallback LocaleDetectionStrategy = "callback"
)

// I18nOptions configures translated API error messages.
type I18nOptions struct {
	Translations    map[string]map[string]string
	DefaultLocale   string
	Detection       []LocaleDetectionStrategy
	LocaleCookie    string
	UserLocaleField string
	GetLocale       func(*auth.Context) string
}

// I18n translates API error messages while preserving status and error code.
func I18n(opts I18nOptions) auth.Plugin {
	detection := opts.Detection
	if len(detection) == 0 {
		detection = []LocaleDetectionStrategy{LocaleFromHeader}
	}
	defaultLocale := opts.DefaultLocale
	if defaultLocale == "" {
		defaultLocale = "en"
	}
	localeCookie := opts.LocaleCookie
	if localeCookie == "" {
		localeCookie = "locale"
	}
	userLocaleField := opts.UserLocaleField
	if userLocaleField == "" {
		userLocaleField = "locale"
	}
	return basePlugin{
		id: constants.PluginI18n,
		hooks: &auth.PluginHooks{Before: []func(*auth.Context) bool{
			func(c *auth.Context) bool {
				c.SetErrorTranslator(func(err *apierror.Error) *apierror.Error {
					locale := detectLocale(c, opts.Translations, defaultLocale, detection, localeCookie, userLocaleField, opts.GetLocale)
					translation := opts.Translations[locale][err.Code]
					if translation == "" {
						return err
					}
					return apierror.New(err.Status, err.Code, translation)
				})
				return true
			},
		}},
	}
}

func detectLocale(c *auth.Context, translations map[string]map[string]string, defaultLocale string, detection []LocaleDetectionStrategy, localeCookie string, userLocaleField string, getLocale func(*auth.Context) string) string {
	for _, strategy := range detection {
		switch strategy {
		case LocaleFromHeader:
			if locale := firstAvailableLocale(parseAcceptLanguage(c.R.Header.Get("Accept-Language")), translations); locale != "" {
				return locale
			}
		case LocaleFromCookie:
			if cookie, err := c.R.Cookie(localeCookie); err == nil && translations[cookie.Value] != nil {
				return cookie.Value
			}
		case LocaleFromSession:
			if _, user, err := c.GetSession(); err == nil && user.Additional != nil {
				if locale, ok := user.Additional[userLocaleField].(string); ok && translations[locale] != nil {
					return locale
				}
			}
		case LocaleFromCallback:
			if getLocale != nil {
				locale := getLocale(c)
				if translations[locale] != nil {
					return locale
				}
			}
		}
	}
	if translations[defaultLocale] != nil {
		return defaultLocale
	}
	return firstTranslationLocale(translations)
}

func parseAcceptLanguage(header string) []string {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	type weightedLocale struct {
		locale string
		weight float64
		index  int
	}
	parts := strings.Split(header, ",")
	locales := make([]weightedLocale, 0, len(parts))
	for index, part := range parts {
		segments := strings.Split(strings.TrimSpace(part), ";")
		locale := strings.TrimSpace(segments[0])
		if locale == "" {
			continue
		}
		if dash := strings.Index(locale, "-"); dash >= 0 {
			locale = locale[:dash]
		}
		weight := 1.0
		if len(segments) > 1 {
			q := strings.TrimSpace(segments[1])
			q = strings.TrimPrefix(q, "q=")
			parsed, err := strconv.ParseFloat(q, 64)
			if err == nil {
				weight = parsed
			}
		}
		locales = append(locales, weightedLocale{locale: locale, weight: weight, index: index})
	}
	sort.SliceStable(locales, func(i, j int) bool {
		if locales[i].weight == locales[j].weight {
			return locales[i].index < locales[j].index
		}
		return locales[i].weight > locales[j].weight
	})
	out := make([]string, 0, len(locales))
	for _, locale := range locales {
		out = append(out, locale.locale)
	}
	return out
}

func firstAvailableLocale(locales []string, translations map[string]map[string]string) string {
	for _, locale := range locales {
		if translations[locale] != nil {
			return locale
		}
	}
	return ""
}

func firstTranslationLocale(translations map[string]map[string]string) string {
	keys := make([]string, 0, len(translations))
	for locale := range translations {
		keys = append(keys, locale)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}
