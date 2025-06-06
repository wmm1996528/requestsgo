package main

import (
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestRawConn(t *testing.T) {
	resp, err := requests.Get(nil, "https://httpbin.org/anything")
	if err != nil {
		t.Error(err)
	}
	if resp.Body() != nil {
		t.Error("conn is not nil")
	}
	resp, err = requests.Get(nil, "https://httpbin.org/anything", requests.RequestOption{Stream: true})
	if err != nil {
		t.Error(err)
	}
	if resp.Body() == nil {
		t.Error("conn is nil")
	}
}
