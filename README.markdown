# Installation

    goinstall github.com/alloy-d/goauth

# Usage

    import (
        "github.com/alloy-d/goauth"
        "os"
    )

    func someFuncThatDoesStuffWithOAuth() (err os.Error) {
        o := new (oauth.OAuth)
        o.ConsumerKey = "key"
        o.ConsumerSecret = "secret"
        o.Callback = "callback"

        o.RequestTokenURL = "https://api.twitter.com/oauth/request_token"
        o.OwnerAuthURL = "https://api.twitter.com/oauth/authorize"
        o.AccessTokenURL = "https://api.twitter.com/oauth/access_token"

        err = o.GetRequestToken()
        if err != nil { return }

        url, err := o.AuthorizationURL()
        if err != nil { return }

        // somehow send user to url...

        var verifier string
        // somehow get verifier (or "PIN")...

        err = o.GetAccessToken(verifier)
        if err != nil { return }

        err = o.Save(os.Getenv("HOME") + "/.simple_example.oauth")

        response, err := o.Post(
            "https://api.twitter.com/1/statuses/update.json",
            map[string]string{"status": "Just did a little OAuth dance!"})
        if err != nil { return }

        // do stuff with response...

        return nil
    }

# Status

This is still a bit of a work in progress.  The interface is subject to
change (and become prettier), but I think it's mostly done.

It is probably obvious that it's rough around the edges in spots.
Please let me know if anything's broken.
