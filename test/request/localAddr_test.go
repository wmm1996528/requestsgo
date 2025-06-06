package main

import (
	"net"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestLocalAddr(t *testing.T) {
	resp, err := requests.Get(nil, "https://httpbin.org/anything", requests.RequestOption{
		ClientOption: requests.ClientOption{
			DialOption: requests.DialOption{
				LocalAddr: &net.TCPAddr{ //set dns server
					IP: net.ParseIP("192.168.1.239"),
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 {
		t.Fatal("http status code is not 200")
	}
}
