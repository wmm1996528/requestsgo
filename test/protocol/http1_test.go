package main

import (
	"log"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestHttp1(t *testing.T) {
	resp, err := requests.Get(nil, "https://httpbin.org/anything", requests.RequestOption{
		ClientOption: requests.ClientOption{

			ForceHttp1: true,
			Logger: func(l requests.Log) {
				log.Print(l)
			},
			ErrCallBack: func(ctx *requests.Response) error {
				log.Print(ctx.Err())
				return nil
			},
		},
	})
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode() != 200 {
		t.Error("resp.StatusCode!= 200")
	}
	if resp.Proto() != "HTTP/1.1" {
		t.Error("resp.Proto!= HTTP/1.1")
	}
}
