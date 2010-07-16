include $(GOROOT)/src/Make.$(GOARCH)

TARG=alloy-d/oauth
GOFILES=oauth.go\
		http.go\
		url.go\

include $(GOROOT)/src/Make.pkg

