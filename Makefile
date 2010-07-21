include $(GOROOT)/src/Make.$(GOARCH)

TARG=alloy-d/goauth
GOFILES=oauth.go\
		http.go\
		url.go\
		helpers.go\
		persist.go\
		error.go\

include $(GOROOT)/src/Make.pkg

