package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

var version = "dev"

type Param struct {
	CookiesFile  *string
	Port         *string
	Target       *string
	AllowOrigins *string
	NoInit       *bool
	Verbose      *bool
	Version      *bool
}

func getParam() *Param {
	cookiesfile, err := os.UserHomeDir()
	if err != nil {
		cookiesfile = "cookies.json"
	} else {
		cookiesfile = path.Join(cookiesfile, ".config", "strava-heatmap-proxy", "strava-cookies.json")
	}
	param := &Param{
		CookiesFile:  flag.String("cookies", cookiesfile, "Path to the cookies file"),
		Port:         flag.String("port", "8080", "Local proxy port"),
		Target:       flag.String("target", "https://content-a.strava.com/", "Heatmap provider URL"),
		AllowOrigins: flag.String("allow-origins", "", "JSON array of allowed CORS origins (supports wildcards like https://*.example.com), e.g. '[\"https://a\",\"https://*.b\"]'"),
		NoInit:       flag.Bool("no-init", false, "Don't try to refresh CloudFront cookies on startup"),
		Verbose:      flag.Bool("verbose", false, "Verbose logging"),
		Version:      flag.Bool("version", false, "Print version and exit"),
	}
	flag.Parse()
	return param
}

type cookieEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type StravaSessionClient struct {
	mu                          sync.RWMutex
	sessionIdentifier           string
	cloudFrontCookies           []*http.Cookie
	cloudFrontCookiesExpiration time.Time
}

func NewStravaSessionClient(cookiesFilePath string) (*StravaSessionClient, error) {
	file, err := os.Open(cookiesFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var entries []cookieEntry
	if err := json.NewDecoder(file).Decode(&entries); err != nil {
		return nil, fmt.Errorf("error decoding json: %w", err)
	}

	client := &StravaSessionClient{}
	for _, entry := range entries {
		if entry.Name == "_strava4_session" {
			client.sessionIdentifier = entry.Value
			break
		}
	}
	if client.sessionIdentifier == "" {
		return nil, fmt.Errorf("_strava4_session not found in cookies file")
	}

	if err := client.readCloudFrontCookiesFromFile(entries); err != nil {
		log.Printf("No valid CloudFront cookies found in file: %v", err)
	}

	return client, nil
}

func (c *StravaSessionClient) readCloudFrontCookiesFromFile(entries []cookieEntry) error {
	var cookies []*http.Cookie
	var expiration int64

	for _, entry := range entries {
		switch entry.Name {
		case "CloudFront-Signature", "CloudFront-Policy", "CloudFront-Key-Pair-Id", "_strava_idcf", "_strava4_session":
			if entry.Value != "" {
				cookies = append(cookies, &http.Cookie{Name: entry.Name, Value: entry.Value})
			}
		case "_strava_CloudFront-Expires":
			var err error
			expiration, err = strconv.ParseInt(entry.Value, 10, 64)
			if err != nil {
				log.Printf("Invalid timestamp value for %s: %s", entry.Name, entry.Value)
			}
		}
	}

	if len(cookies) < 4 {
		return fmt.Errorf("not all required CloudFront cookies found in file")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cloudFrontCookies = cookies
	if expiration != 0 {
		c.cloudFrontCookiesExpiration = time.UnixMilli(expiration)
		log.Printf("CloudFront cookies from file will expire at %s", c.cloudFrontCookiesExpiration)
	}

	return nil
}

// cookieState returns a copy of the current CloudFront cookies and their expiration.
func (c *StravaSessionClient) cookieState() ([]*http.Cookie, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cookies := make([]*http.Cookie, len(c.cloudFrontCookies))
	copy(cookies, c.cloudFrontCookies)
	return cookies, c.cloudFrontCookiesExpiration
}

// health reports whether the already-loaded Strava session and CloudFront
// cookies are present and unexpired at now. It never fetches new cookies.
func (c *StravaSessionClient) health(now time.Time) (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.sessionIdentifier == "" {
		return time.Time{}, errors.New("no Strava session loaded")
	}
	if len(c.cloudFrontCookies) < 4 || c.cloudFrontCookiesExpiration.IsZero() {
		return time.Time{}, errors.New("CloudFront cookies not loaded")
	}
	if !now.Before(c.cloudFrontCookiesExpiration) {
		return c.cloudFrontCookiesExpiration, errors.New("CloudFront cookies expired")
	}
	return c.cloudFrontCookiesExpiration, nil
}

// wildcardOrigin matches an origin scheme plus a domain and all its
// subdomains, e.g. scheme "https" and domain "wanderstories.space" matches
// https://wanderstories.space and https://studio.wanderstories.space, but
// not https://evilwanderstories.space or http://studio.wanderstories.space.
type wildcardOrigin struct {
	scheme string
	domain string
}

type originAllowlist struct {
	// using a map of empty structs for quick membership checks in O(1)
	exact     map[string]struct{}
	wildcards []wildcardOrigin
}

func (a *originAllowlist) allows(origin string) bool {
	if a == nil || origin == "" {
		return false
	}
	if _, ok := a.exact[origin]; ok {
		return true
	}
	if len(a.wildcards) == 0 {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}
	for _, w := range a.wildcards {
		if !strings.EqualFold(parsed.Scheme, w.scheme) {
			continue
		}
		if host == w.domain || strings.HasSuffix(host, "."+w.domain) {
			return true
		}
	}
	return false
}

func parseAllowedOrigins(allowedOrigins string) (*originAllowlist, error) {
	var urls []string
	if err := json.Unmarshal([]byte(allowedOrigins), &urls); err != nil {
		return nil, fmt.Errorf("invalid JSON for cors-whitelist: %w", err)
	}
	allowlist := &originAllowlist{exact: make(map[string]struct{}, len(urls))}
	for _, u := range urls {
		if u == "" {
			continue
		}
		if !strings.Contains(u, "*") {
			// initialize an empty struct
			allowlist.exact[u] = struct{}{}
			continue
		}
		// Wildcard entries look like "https://*.wanderstories.space"
		// ("https://*wanderstories.space" is accepted as equivalent).
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme == "" {
			return nil, fmt.Errorf("invalid wildcard origin %q", u)
		}
		host := parsed.Hostname()
		if !strings.HasPrefix(host, "*") || strings.Count(host, "*") != 1 {
			return nil, fmt.Errorf("invalid wildcard origin %q: '*' must start the host", u)
		}
		domain := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(host, "*"), "."))
		if domain == "" || strings.Contains(domain, "*") {
			return nil, fmt.Errorf("invalid wildcard origin %q: missing domain after '*'", u)
		}
		allowlist.wildcards = append(allowlist.wildcards, wildcardOrigin{
			scheme: strings.ToLower(parsed.Scheme),
			domain: domain,
		})
	}
	return allowlist, nil
}

func (c *StravaSessionClient) fetchCloudFrontCookies() error {
	req, err := http.NewRequest("HEAD", "https://www.strava.com/maps", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Cookie", fmt.Sprintf("_strava4_session=%s;", c.sessionIdentifier))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var cookies []*http.Cookie
	var expiration int64

	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "CloudFront-Signature", "CloudFront-Policy", "CloudFront-Key-Pair-Id", "_strava_idcf", "_strava4_session":
			if cookie.Value != "" {
				cookies = append(cookies, cookie)
			}
		case "_strava_CloudFront-Expires":
			expiration, err = strconv.ParseInt(cookie.Value, 10, 64)
			if err != nil {
				log.Printf("Invalid timestamp value for %s: %s", cookie.Name, cookie.Value)
			}
		}
	}

	if len(cookies) < 4 {
		return fmt.Errorf("not all required CloudFront cookies received")
	}

	hasSession := false
	for _, cookie := range cookies {
		if cookie.Name == "_strava4_session" {
			hasSession = true
			break
		}
	}
	if !hasSession {
		cookies = append(cookies, &http.Cookie{Name: "_strava4_session", Value: c.sessionIdentifier})
	}

	c.mu.Lock()
	c.cloudFrontCookies = cookies
	if expiration != 0 {
		c.cloudFrontCookiesExpiration = time.UnixMilli(expiration)
	}
	c.mu.Unlock()
	if expiration != 0 {
		log.Printf("New CloudFront cookies will expire at %s", time.UnixMilli(expiration))
	}

	return nil
}

type healthResponse struct {
	Status    string `json:"status"`
	ExpiresAt string `json:"cloudfront_cookies_expire_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func serveHealth(w http.ResponseWriter, req *http.Request, client *StravaSessionClient) {
	expiresAt, err := client.health(time.Now())
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("Health check failed: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		if req.Method != http.MethodHead {
			resp := healthResponse{Status: "error", Error: err.Error()}
			if !expiresAt.IsZero() {
				resp.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	if req.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:    "ok",
			ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		})
	}
}

func rootHandler(client *StravaSessionClient, proxy http.Handler, allowedOrigins *originAllowlist, verbose bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
			serveHealth(w, req, client)
			return
		}
		origin := req.Header.Get("Origin")
		if origin != "" {
			if !allowedOrigins.allows(origin) {
				if verbose {
					log.Printf("Got request with non-whitelisted origin %s", origin)
				}
				http.Error(w, "Forbidden origin", http.StatusForbidden)
				return
			}
		}
		proxy.ServeHTTP(w, req)
	}
}

func main() {
	param := getParam()
	if *param.Version {
		fmt.Println("strava-heatmap-proxy", version)
		return
	}
	target, err := url.Parse(*param.Target)
	if err != nil {
		log.Fatalf("Could not parse target url: %s", err)
	}

	client, err := NewStravaSessionClient(*param.CookiesFile)
	if err != nil {
		log.Fatalf("Could not initialize Strava client: %s", err)
	}

	if cookies, expiration := client.cookieState(); len(cookies) == 0 || (!*param.NoInit && time.Now().After(expiration)) {
		log.Printf("Fetching new CloudFront cookies...")
		if err := client.fetchCloudFrontCookies(); err != nil {
			log.Fatalf("Warning: Failed to fetch CloudFront cookies: %s", err)
		}
	}

	var allowedOrigins *originAllowlist
	if *param.AllowOrigins != "" {
		allowedOrigins, err = parseAllowedOrigins(*param.AllowOrigins)
		if err != nil {
			log.Fatalf("Could not parse allowed origins: %v", err)
		}
	}

	rewrite := func(preq *httputil.ProxyRequest) {
		preq.Out.URL.Scheme = target.Scheme
		preq.Out.URL.Host = target.Host
		if target.Path != "" {
			preq.Out.URL.Path = path.Join(target.Path, preq.In.URL.Path)
		}
		preq.Out.Host = target.Host
		// refresh expired CloudFront cookies before forwarding the request
		if _, expiration := client.cookieState(); expiration.IsZero() || time.Now().After(expiration) {
			log.Printf("CloudFront cookies have expired, refreshing...")
			if err := client.fetchCloudFrontCookies(); err != nil {
				log.Fatalf("Warning: Failed to fetch CloudFront cookies: %s", err)
			}
		}
		cookies, _ := client.cookieState()
		for _, c := range cookies {
			preq.Out.AddCookie(c)
		}
		if *param.Verbose {
			log.Printf("Got request: %s", preq.In.URL)
		}
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: rewrite,
		ModifyResponse: func(resp *http.Response) error {
			origin := resp.Request.Header.Get("Origin")
			if origin != "" {
				if allowedOrigins.allows(origin) {
					resp.Header.Set("Access-Control-Allow-Origin", origin)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				if *param.Verbose {
					log.Printf("Client canceled request: %s %s: %v", req.Method, req.URL, err)
				}
				return
			}
			log.Printf("Proxy error for %s %s: %v", req.Method, req.URL, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}

	http.HandleFunc("/", rootHandler(client, proxy, allowedOrigins, *param.Verbose))

	log.Printf("Started proxy %s for target %s on http://localhost:%s/ ..", version, *param.Target, *param.Port)
	log.Fatal(http.ListenAndServe(":"+*param.Port, nil))
}
