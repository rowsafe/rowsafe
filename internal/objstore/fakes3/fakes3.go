// Package fakes3 is an in-memory S3 server for tests: PUT, GET, DELETE,
// ListObjectsV2 and multipart uploads, path-style, without signature checks
// (it only requires an Authorization header).
package fakes3

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is a fake S3 endpoint for one bucket.
type Server struct {
	*httptest.Server
	Bucket string

	mu      sync.Mutex
	objects map[string][]byte
	uploads map[string]map[int][]byte
	nextID  int
	// Fail, when set, is called for each request; a non-zero status is
	// returned instead of handling it.
	Fail func(r *http.Request) int
}

// New starts a fake S3 server (plain HTTP).
func New(bucket string) *Server {
	s := &Server{Bucket: bucket, objects: map[string][]byte{}, uploads: map[string]map[int][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Host is host:port of the server.
func (s *Server) Host() string { return strings.TrimPrefix(s.URL, "http://") }

// Keys lists the stored keys.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Object returns a stored object.
func (s *Server) Object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	return b, ok
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "no auth", http.StatusForbidden)
		return
	}
	if s.Fail != nil {
		if code := s.Fail(r); code != 0 {
			w.WriteHeader(code)
			fmt.Fprintf(w, "<Error><Code>Injected</Code><Message>injected failure</Message></Error>")
			return
		}
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	if bucket != s.Bucket {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "<Error><Code>NoSuchBucket</Code></Error>")
		return
	}
	q := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && key == "" && q.Get("list-type") == "2":
		prefix := q.Get("prefix")
		var keys []string
		for k := range s.objects {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		start := 0
		if t := q.Get("continuation-token"); t != "" {
			start, _ = strconv.Atoi(t)
		}
		const page = 3 // small pages exercise continuation
		end := min(start+page, len(keys))
		var b strings.Builder
		b.WriteString("<ListBucketResult>")
		for _, k := range keys[start:end] {
			fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified></Contents>",
				k, len(s.objects[k]), time.Now().UTC().Format(time.RFC3339))
		}
		if end < len(keys) {
			fmt.Fprintf(&b, "<IsTruncated>true</IsTruncated><NextContinuationToken>%d</NextContinuationToken>", end)
		} else {
			b.WriteString("<IsTruncated>false</IsTruncated>")
		}
		b.WriteString("</ListBucketResult>")
		io.WriteString(w, b.String())
	case r.Method == http.MethodPost && q.Has("uploads"):
		s.nextID++
		id := strconv.Itoa(s.nextID)
		s.uploads[id] = map[int][]byte{}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		up, ok := s.uploads[q.Get("uploadId")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n, _ := strconv.Atoi(q.Get("partNumber"))
		body, _ := io.ReadAll(r.Body)
		up[n] = body
		w.Header().Set("ETag", fmt.Sprintf("\"etag-%d\"", n))
	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		up, ok := s.uploads[q.Get("uploadId")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var cmu struct {
			Parts []struct {
				PartNumber int `xml:"PartNumber"`
			} `xml:"Part"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := xml.Unmarshal(body, &cmu); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var all []byte
		for _, p := range cmu.Parts {
			all = append(all, up[p.PartNumber]...)
		}
		s.objects[key] = all
		delete(s.uploads, q.Get("uploadId"))
		io.WriteString(w, "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>")
	case r.Method == http.MethodDelete && q.Get("uploadId") != "":
		delete(s.uploads, q.Get("uploadId"))
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		s.objects[key] = body
	case r.Method == http.MethodGet:
		b, ok := s.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
			return
		}
		w.Write(b)
	case r.Method == http.MethodDelete:
		delete(s.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
