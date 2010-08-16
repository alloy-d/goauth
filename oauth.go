// A Go OAuth library, mainly created to interact with Twitter.
// 
// Does header-based OAuth over HTTP or HTTPS.
package oauth

import (
    "crypto/hmac"
    "encoding/base64"
    "fmt"
    "http"
    "io"
    "os"
    "rand"
    "sort"
    "strconv"
    "time"
)

// Supported oauth version (currently the only legal value):
const OAUTH_VERSION = "1.0"

// Supported signature methods:
const (
    HMAC_SHA1 = "HMAC-SHA1"
)

// Request types:
const (
    TempCredentialReq = iota
    OwnerAuthorization
    TokenReq
)

type OAuth struct {
    ConsumerKey string
    ConsumerSecret string
    SignatureMethod string

    Callback string

    RequestTokenURL string
    OwnerAuthURL string
    AccessTokenURL string

    // NOT initialized.
    RequestTokenParams map[string]string

    requestToken string
    requestSecret string

    userName string
    userId uint
    accessToken string
    accessSecret string
}

// An empty map[string]string.
// Caters to laziness when no params are given.
var None map[string]string

func (o *OAuth) Authorized() bool {
    if o.accessToken != "" && o.accessSecret != "" {
        return true
    }
    return false
}

// Returns the user id, if any.
//
// Does not return any dance errors, because that would just be
// obnoxious.  Check for authorization with Authorized().
func (o *OAuth) UserID() uint {
    return o.userId
}

// Returns the username, if any.
//
// Does not return any dance errors.  Check for authorization with
// Authorized().
func (o *OAuth) UserName() string {
    return o.userName
}

// Initiates the OAuth dance.
func (o *OAuth) GetRequestToken() (err os.Error) {
    oParams := o.params()
    oParams["oauth_callback"] = o.Callback

    allParams := mergeParams(oParams, o.RequestTokenParams)

    resp, err := o.makeRequest("POST", o.RequestTokenURL, allParams, None)
    if err != nil {
        return
    }
    err = o.parseResponse(resp.StatusCode, resp.Body, TempCredentialReq)
    return
}

// Makes an HTTP request, handling all the repetitive OAuth overhead.
func (o *OAuth) makeRequest(method, url string, oParams map[string]string, params map[string]string) (resp *http.Response, err os.Error) {
    escapeParams(oParams)
    escapeParams(params)

    allParams := mergeParams(oParams, params)
    signature, err := o.sign(baseString(method, url, allParams))
    if err != nil {
        return
    }

    oParams["oauth_signature"] = PercentEncode(signature)

    switch(method) {
    case "POST":
        resp, err = post(addQueryParams(url, params), oParams)
    case "GET":
        resp, err = get(addQueryParams(url, params), oParams)
    default:
        return nil, &implementationError{
            What: fmt.Sprintf("HTTP method (%s)", method),
            Where: "OAuth\xb7makeRequest()",
        }
    }
    return
}

// The URL the user needs to visit to grant authorization.
// Call after GetRequestToken().
func (o *OAuth) AuthorizationURL() (string, os.Error) {
    if o.requestToken == "" || o.requestSecret == "" {
        return "", &danceError{
            What: "attempt to get authorization without credentials",
            Where: "OAuth\xb7AuthorizationURL()",
        }
    }

    url := o.OwnerAuthURL + "?oauth_token=" + o.requestToken
    return url, nil
}

// Performs the final step in the dance: getting the access token.
//
// Call this after GetRequestToken() and getting user verification.
func (o *OAuth) GetAccessToken(verifier string) (err os.Error) {
    if o.requestToken == "" || o.requestSecret == "" {
        return &danceError{
            What: "Temporary credentials not avaiable",
            Where: "OAuth\xb7GetAccessToken()",
        }
    }

    params := o.params()
    params["oauth_token"] = o.requestToken
    params["oauth_verifier"] = verifier
    resp, err := o.makeRequest("POST", o.AccessTokenURL, params, None)
    if err != nil {
        return
    }

    return o.parseResponse(resp.StatusCode, resp.Body, TokenReq)
}

// Parses a response for the OAuth dance and sets the appropriate fields
// in o for the request type.
func (o *OAuth) parseResponse(status int, body io.Reader, requestType int) os.Error {
    //dump, _ := http.DumpResponse(resp, true)
    //fmt.Fprintf(os.Stderr, "%s\n", dump)
    r := bodyString(body)

    if status == 401 {
        return &danceError{
            What: r,
            Where: fmt.Sprintf("parseResponse(requestType=%d)", requestType),
        }
    }

    params := parseParams(r)

    switch(requestType) {
    case TempCredentialReq:
        o.requestToken = params["oauth_token"]
        o.requestSecret = params["oauth_token_secret"]
        if confirmed, ok := params["oauth_callback_confirmed"]; !ok ||
            confirmed != "true" {
            return &callbackError{o.Callback}
        }
    case TokenReq:
        o.accessToken = params["oauth_token"]
        o.accessSecret = params["oauth_token_secret"]
        o.userId, _ = strconv.Atoui(params["user_id"])
        o.userName = params["screen_name"]
    default:
        return &implementationError{
            What: "requestType=" + strconv.Itoa(requestType),
            Where: "OAuth\xb7parseResponse()",
        }
    }
    return nil
}

func (o *OAuth) params() (p map[string]string) {
    p = make(map[string]string)
    p["oauth_consumer_key"] = o.ConsumerKey
    p["oauth_signature_method"] = o.SignatureMethod
    p["oauth_timestamp"] = timestamp()
    p["oauth_nonce"] = nonce()
    p["oauth_version"] = OAUTH_VERSION
    if o.Authorized() {
        p["oauth_token"] = o.accessToken
    }
    return
}

// The base string used to compute signatures.
//
// Pass in all parameters, (query params, oauth params, post body).
func baseString(method, url string, params map[string]string) string {
    str := method + "&"
    str += PercentEncode(url)

    keys := make([]string, len(params))
    i := 0
    for k, _ := range params {
        keys[i] = k
        i++
    }

    sort.SortStrings(keys)
    first := true
    for _, k := range keys {
        if first {
            str += "&"
            first = false
        } else {
            str += "%26"
        }
        str += PercentEncode(k) + "%3D"
        str += PercentEncode(params[k])
    }
    return str
}

// For oauth_nonce (if that wasn't obvious).
func nonce() string {
    return strconv.Itoa64(rand.Int63())
}

// This could probably seem like less of a hack...
func (o *OAuth) signingKey() string {
    key := o.ConsumerSecret + "&"
    if o.accessSecret != "" {
        key += o.accessSecret
    } else if o.requestSecret != "" {
        key += o.requestSecret
    }
    return key
}

func (o *OAuth) sign(request string) (string, os.Error) {
    key := o.signingKey()
    switch (o.SignatureMethod) {
    case HMAC_SHA1:
        hash := hmac.NewSHA1([]byte(key))
        hash.Write([]byte(request))
        signature := hash.Sum()
        digest := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
        base64.StdEncoding.Encode(digest, signature)
        return string(digest), nil
    }
    return "", &implementationError{
        What: fmt.Sprintf("Unknown signature method (%d)", o.SignatureMethod),
        Where: "OAuth\xb7sign",
    }
}

func timestamp() string {
    return strconv.Itoa64(time.Seconds())
}

func (o *OAuth) Post(url string, params map[string]string) (r *http.Response, err os.Error) {
    if !o.Authorized() {
        return nil, &danceError{
            What: "Not authorized",
            Where: "OAuth\xb7PostParams()",
        }
    }

    oParams := o.params()
    r, err = o.makeRequest("POST", url, oParams, params)
    return
}

func (o *OAuth) Get(url string, params map[string]string) (r *http.Response, err os.Error) {
    if !o.Authorized() {
        return nil, &danceError{
            What: "Not authorized",
            Where: "OAuth\xb7PostParams()",
        }
    }

    oParams := o.params()
    r, err = o.makeRequest("GET", url, oParams, params)
    return
}
