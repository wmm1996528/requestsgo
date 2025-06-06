package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestRequestCallBack(t *testing.T) {
	_, err := requests.Get(nil, "https://httpbin.org/anything", requests.RequestOption{
		ClientOption: requests.ClientOption{
			RequestCallBack: func(ctx *requests.Response) error {
				response := ctx.Response()
				if response != nil {
					if response.ContentLength > 100 {
						return errors.New("max length")
					}
				}
				return nil
			},
		},
	})
	if !strings.Contains(err.Error(), "max length") {
		t.Error("err is not max length")
	}
}
