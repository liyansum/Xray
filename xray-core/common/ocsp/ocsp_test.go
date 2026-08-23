package ocsp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func useTestHTTPClient(t *testing.T, fn roundTripFunc) {
	t.Helper()
	previous := ocspHTTPClient
	ocspHTTPClient = &http.Client{Transport: fn}
	t.Cleanup(func() { ocspHTTPClient = previous })
}

func TestDoRequestRejectsHTTPErrorAndOversizedBody(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		useTestHTTPClient(t, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Body: io.NopCloser(bytes.NewReader(nil))}, nil
		})
		if _, err := doRequest(context.Background(), http.MethodGet, "http://ocsp.test", "", nil, 64); err == nil {
			t.Fatal("accepted an unsuccessful HTTP response")
		}
	})

	t.Run("size", func(t *testing.T) {
		useTestHTTPClient(t, func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(make([]byte, 65)))}, nil
		})
		if _, err := doRequest(context.Background(), http.MethodGet, "http://ocsp.test", "", nil, 64); err == nil {
			t.Fatal("accepted an oversized HTTP response")
		}
	})
}

func TestDoRequestHonorsContext(t *testing.T) {
	useTestHTTPClient(t, func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := doRequest(ctx, http.MethodGet, "http://ocsp.test", "", nil, 64); err == nil {
		t.Fatal("request ignored its context deadline")
	}
}
