// A Go OAuth library, mainly created to interact with Twitter.
// 
// Does header-based OAuth over HTTP or HTTPS.
package oauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
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
	ConsumerKey     string
	ConsumerSecret  string
	SignatureMethod string

	Callback string

	RequestTokenURL string
	OwnerAuthURL    string
	AccessTokenURL  string

	AccessToken  string
	AccessSecret string

	// NOT initialized.
	RequestTokenParams map[string]string

	RequestToken  string
	RequestSecret string

	userName string
	userId   uint
}

// An empty map[string]string.
// Caters to laziness when no params are given.
var None map[string]string

func (o *OAuth) Authorized() bool {
	if o.AccessToken != "" && o.AccessSecret != "" {
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
func (o *OAuth) GetRequestToken() (err error) {
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
func (o *OAuth) makeRequest(method, url string, oParams map[string]string, params map[string]string) (resp *http.Response, err error) {
	escapeParams(oParams)
	escapeParams(params)

	allParams := mergeParams(oParams, params)
	signature, err := o.sign(baseString(method, url, allParams))
	if err != nil {
		return
	}

	oParams["oauth_signature"] = PercentEncode(signature)

	switch method {
	case "POST":
		resp, err = post(addQueryParams(url, params), oParams)
	case "GET":
		resp, err = get(addQueryParams(url, params), oParams)
	default:
		return nil, &implementationError{
			What:  fmt.Sprintf("HTTP method (%s)", method),
			Where: "OAuth\xb7makeRequest()",
		}
	}
	return
}

// The URL the user needs to visit to grant authorization.
// Call after GetRequestToken().
func (o *OAuth) AuthorizationURL() (string, error) {
	if o.RequestToken == "" || o.RequestSecret == "" {
		return "", &danceError{
			What:  "attempt to get authorization without credentials",
			Where: "OAuth\xb7AuthorizationURL()",
		}
	}

	url := o.OwnerAuthURL + "?oauth_token=" + o.RequestToken
	return url, nil
}

// Performs the final step in the dance: getting the access token.
//
// Call this after GetRequestToken() and getting user verification.
func (o *OAuth) GetAccessToken(verifier string) (err error) {
	if o.RequestToken == "" || o.RequestSecret == "" {
		return &danceError{
			What:  "Temporary credentials not avaiable",
			Where: "OAuth\xb7GetAccessToken()",
		}
	}

	params := o.params()
	params["oauth_token"] = o.RequestToken
	params["oauth_verifier"] = verifier
	resp, err := o.makeRequest("POST", o.AccessTokenURL, params, None)
	if err != nil {
		return
	}

	return o.parseResponse(resp.StatusCode, resp.Body, TokenReq)
}

// Parses a response for the OAuth dance and sets the appropriate fields
// in o for the request type.
func (o *OAuth) parseResponse(status int, body io.Reader, requestType int) error {
	//dump, _ := http.DumpResponse(resp, true)
	//fmt.Fprintf(os.Stderr, "%s\n", dump)
	r := bodyString(body)

	if status == 401 {
		return &danceError{
			What:  r,
			Where: fmt.Sprintf("parseResponse(requestType=%d)", requestType),
		}
	}

	params := parseParams(r)

	switch requestType {
	case TempCredentialReq:
		o.RequestToken = params["oauth_token"]
		o.RequestSecret = params["oauth_token_secret"]
		if confirmed, ok := params["oauth_callback_confirmed"]; !ok ||
			confirmed != "true" {
			return &callbackError{o.Callback}
		}
	case TokenReq:
		o.AccessToken = params["oauth_token"]
		o.AccessSecret = params["oauth_token_secret"]
		n, _ := strconv.ParseUint(params["user_id"], 10, 0)
		o.userId = uint(n)
		o.userName = params["screen_name"]
	default:
		return &implementationError{
			What:  "requestType=" + strconv.Itoa(requestType),
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
		p["oauth_token"] = o.AccessToken
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

	sort.Strings(keys)
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
	return strconv.FormatInt(rand.Int63(), 10)
}

// This could probably seem like less of a hack...
func (o *OAuth) signingKey() string {
	key := o.ConsumerSecret + "&"
	if o.AccessSecret != "" {
		key += o.AccessSecret
	} else if o.RequestSecret != "" {
		key += o.RequestSecret
	}
	return key
}

func (o *OAuth) sign(request string) (string, error) {
	key := o.signingKey()
	switch o.SignatureMethod {
	case HMAC_SHA1:
		hash := hmac.New(sha1.New, []byte(key))
		hash.Write([]byte(request))
		signature := hash.Sum(nil)
		digest := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
		base64.StdEncoding.Encode(digest, signature)
		return string(digest), nil
	}
	return "", &implementationError{
		What:  fmt.Sprintf("Unknown signature method (%d)", o.SignatureMethod),
		Where: "OAuth\xb7sign",
	}
}

func timestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func (o *OAuth) Post(url string, params map[string]string) (r *http.Response, err error) {
	if !o.Authorized() {
		return nil, &danceError{
			What:  "Not authorized",
			Where: "OAuth\xb7PostParams()",
		}
	}

	oParams := o.params()
	r, err = o.makeRequest("POST", url, oParams, params)
	return
}

func (o *OAuth) Get(url string, params map[string]string) (r *http.Response, err error) {
	if !o.Authorized() {
		return nil, &danceError{
			What:  "Not authorized",
			Where: "OAuth\xb7PostParams()",
		}
	}

	oParams := o.params()
	r, err = o.makeRequest("GET", url, oParams, params)
	return
}
