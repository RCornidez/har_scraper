package proxy

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"har-scraper/internal/certificate"
	"har-scraper/internal/config"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type HTTPRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body,omitempty"`
}

type HTTPResponse struct {
	StatusCode int                 `json:"status_code"`
	Status     string              `json:"status"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body,omitempty"`
}

type HTTPEvent struct {
	Timestamp time.Time    `json:"timestamp"`
	Request   HTTPRequest  `json:"request"`
	Response  HTTPResponse `json:"response"`
	Duration  float64      `json:"duration_ms"`
}

type EventList struct {
	Events []HTTPEvent `json:"events"`
}

var (
	fileLocks  = make(map[string]*sync.Mutex)
	locksMutex sync.Mutex
)

// Proxy holds dependencies needed by the proxy handlers.
type Proxy struct {
	CA  *certificate.CA
	Cfg *config.Configuration
}

// New creates a new Proxy instance.
func New(cfg *config.Configuration, ca *certificate.CA) *Proxy {
	return &Proxy{CA: ca, Cfg: cfg}
}

func (p *Proxy) HandleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	fullURL := r.URL.String()

	reqBody, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(reqBody)))
	r.RequestURI = ""

	client := &http.Client{}
	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	rawRespBody, _ := io.ReadAll(resp.Body)
	decompressedBody, _ := decompressBody(
		strings.NewReader(string(rawRespBody)),
		resp.Header,
	)

	endTime := time.Now()

	event := HTTPEvent{
		Timestamp: startTime,
		Duration:  float64(endTime.Sub(startTime).Milliseconds()),
		Request: HTTPRequest{
			Method:  r.Method,
			URL:     fullURL,
			Headers: r.Header,
			Body:    string(reqBody),
		},
		Response: HTTPResponse{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Headers:    resp.Header,
			Body:       string(decompressedBody),
		},
	}

	go saveEvent(event, r.URL.Host, p.Cfg)

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(rawRespBody)
}

func (p *Proxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	host := r.Host
	if h, _, err := splitHostPort(host); err == nil {
		host = h
	}

	cert, err := p.CA.GenerateCert(host)
	if err != nil {
		log.Println("Error generating cert:", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Println("TLS handshake error:", err)
		return
	}
	defer tlsClientConn.Close()

	req, err := http.ReadRequest(bufio.NewReader(tlsClientConn))
	if err != nil {
		if err != io.EOF {
			log.Println("Error reading HTTPS request:", err)
		}
		return
	}

	startTime := time.Now()

	reqBody, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(strings.NewReader(string(reqBody)))

	scheme := "https"
	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, req.URL.String())

	req.RequestURI = ""
	req.URL.Scheme = scheme
	req.URL.Host = host

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error forwarding HTTPS request:", err)
		return
	}
	defer resp.Body.Close()

	rawRespBody, _ := io.ReadAll(resp.Body)
	decompressedBody, _ := decompressBody(
		strings.NewReader(string(rawRespBody)),
		resp.Header,
	)

	endTime := time.Now()

	event := HTTPEvent{
		Timestamp: startTime,
		Duration:  float64(endTime.Sub(startTime).Milliseconds()),
		Request: HTTPRequest{
			Method:  req.Method,
			URL:     fullURL,
			Headers: req.Header,
			Body:    string(reqBody),
		},
		Response: HTTPResponse{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Headers:    resp.Header,
			Body:       string(decompressedBody),
		},
	}

	go saveEvent(event, host, p.Cfg)

	resp.Body = io.NopCloser(strings.NewReader(string(rawRespBody)))
	if err := resp.Write(tlsClientConn); err != nil {
		if !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "wsasend") {
			log.Println("Error writing HTTPS response:", err)
		}
	}
}

func decompressBody(body io.Reader, headers map[string][]string) ([]byte, error) {
	if encoding, ok := headers["Content-Encoding"]; ok {
		if len(encoding) > 0 && strings.Contains(strings.ToLower(encoding[0]), "gzip") {
			gzipReader, err := gzip.NewReader(body)
			if err != nil {
				return io.ReadAll(body)
			}
			defer gzipReader.Close()
			return io.ReadAll(gzipReader)
		}
	}
	return io.ReadAll(body)
}

func shouldSaveEvent(event HTTPEvent, cfg *config.Configuration) bool {
	if !cfg.Filters.Enabled {
		return true
	}

	// extract hostname
	parsed, err := url.Parse(event.Request.URL)
	if err != nil {
		return false
	}

	// Check domain patterns
	hostnameMatch := false
	for _, pattern := range cfg.Filters.DomainPatterns {
		if matchPattern(parsed.Hostname(), pattern) {
			hostnameMatch = true
			break
		}
	}

	if !hostnameMatch {
		return false
	}

	// Check response content type
	if len(cfg.Filters.ResponseContentType) == 0 {
		return true
	}

	contentType := event.Response.Headers["Content-Type"]
	if len(contentType) == 0 {
		return false
	}

	for _, allowed := range cfg.Filters.ResponseContentType {
		if strings.Contains(strings.ToLower(contentType[0]), strings.ToLower(allowed)) {
			return true
		}
	}

	return false
}

func matchPattern(url, pattern string) bool {
	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

	if !strings.HasPrefix(pattern, "*") {
		regexPattern = "^" + regexPattern
	}
	if !strings.HasSuffix(pattern, "*") {
		regexPattern = regexPattern + "$"
	}

	matched, err := regexp.MatchString(regexPattern, url)
	if err != nil {
		log.Printf("ERROR: Pattern matching error: %v", err)
		return false
	}
	return matched
}

func getFileLock(path string) *sync.Mutex {
	locksMutex.Lock()
	defer locksMutex.Unlock()

	if _, exists := fileLocks[path]; !exists {
		fileLocks[path] = &sync.Mutex{}
	}
	return fileLocks[path]
}

func saveEvent(event HTTPEvent, host string, cfg *config.Configuration) {
	parsed, _ := url.Parse(event.Request.URL)
	contentType := event.Response.Headers["Content-Type"]
	ct := "none"
	if len(contentType) > 0 {
		ct = contentType[0]
	}

	matched := shouldSaveEvent(event, cfg)

	if !matched {
		if !cfg.Logging.LogMatchesOnly {
			log.Printf("✗ [%s] %s | %s", event.Request.Method, parsed.Hostname(), ct)
		}
		return
	}

	log.Printf("✓ [%s] %s | %s", event.Request.Method, parsed.Hostname(), ct)

	parts := strings.Split(host, ".")
	var domain, subdomain string

	if len(parts) >= 2 {
		domain = strings.Join(parts[len(parts)-2:], ".")
		if len(parts) > 2 {
			subdomain = strings.Join(parts[:len(parts)-2], ".")
		}
	} else {
		domain = host
	}

	var dirPath string
	if subdomain != "" {
		dirPath = filepath.Join("data", domain, subdomain)
	} else {
		dirPath = filepath.Join("data", domain)
	}

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		log.Printf("Error creating directory %s: %v", dirPath, err)
		return
	}

	dateStr := event.Timestamp.Format("20060102")
	filePath := filepath.Join(dirPath, fmt.Sprintf("%s.json", dateStr))

	lock := getFileLock(filePath)
	lock.Lock()
	defer lock.Unlock()

	var eventList EventList
	if data, err := os.ReadFile(filePath); err == nil {
		if err := json.Unmarshal(data, &eventList); err != nil {
			log.Printf("Error unmarshaling existing events: %v", err)
			eventList = EventList{Events: []HTTPEvent{}}
		}
	} else {
		eventList = EventList{Events: []HTTPEvent{}}
	}

	eventList.Events = append(eventList.Events, event)

	data, err := json.MarshalIndent(eventList, "", "  ")
	if err != nil {
		log.Printf("Error marshaling event list: %v", err)
		return
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Printf("Error writing file %s: %v", filePath, err)
		return
	}
}

func splitHostPort(hostport string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(hostport)
	if err != nil {
		return hostport, "", nil
	}
	return host, port, nil
}
