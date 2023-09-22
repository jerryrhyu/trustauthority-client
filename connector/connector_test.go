/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// setup sets up a test HTTP server along with a Connector that is
// configured to talk to that test server. Tests should register handlers on
// mux which provide mock responses for the API method being tested.
func setup() (connector Connector, mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	//apiHandler := http.NewServeMux()
	//apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, mux))

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(mux)

	// connector is the Connector being tested and is
	// configured to use test server.
	cfg := Config{
		BaseUrl: server.URL,
		TlsCfg: &tls.Config{
			InsecureSkipVerify: true,
		},
		ApiUrl: server.URL,
	}
	connector, _ = New(&cfg)

	return connector, mux, server.URL, server.Close
}

func TestNew(t *testing.T) {
	cfg := Config{
		ApiUrl: "https://custom-url/api/v1",
	}

	_, err := New(&cfg)
	if err != nil {
		t.Errorf("New returned unexpected error: %v", err)
	}
}

func TestNewWithRetryConfig(t *testing.T) {

	retryWaitMin := DefaultRetryWaitMinSeconds * time.Second
	retryWaitMax := DefaultRetryWaitMinSeconds * time.Second
	retryMax := DefaultRetryWaitMaxSeconds
	retryConfig := RetryConfig{
		RetryWaitMin: &retryWaitMin,
		RetryWaitMax: &retryWaitMax,
		RetryMax:     &retryMax,
		CheckRetry:   defaultRetryPolicy,
		BackOff:      nil,
	}
	cfg := Config{
		ApiUrl:      "https://custom-url/api/v1",
		RetryConfig: &retryConfig,
	}
	_, err := New(&cfg)
	if err != nil {
		t.Errorf("New returned unexpected error: %v", err)
	}
}

func TestNew_badAPIURL(t *testing.T) {
	cfg := Config{
		ApiUrl: "bogus\napi\nURL",
	}

	if _, err := New(&cfg); err == nil {
		t.Error("New retruned nil, expected error")
	}
}

func TestNew_badBaseURL(t *testing.T) {
	cfg := Config{
		BaseUrl: "bogus\nbase\nURL",
	}

	if _, err := New(&cfg); err == nil {
		t.Error("New retruned nil, expected error")
	}
}
