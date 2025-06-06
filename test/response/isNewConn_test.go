package main

import (
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestDefaultClient(t *testing.T) {
	for i := 0; i < 2; i++ {
		resp, err := requests.Get(nil, "https://httpbin.org/anything")
		if err != nil {
			t.Error(err)
		}
		if i == 1 && resp.IsNewConn() {
			t.Error("new conn error")
		}
	}
}
