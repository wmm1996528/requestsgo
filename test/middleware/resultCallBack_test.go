package main

import (
	"errors"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestResultCallBack(t *testing.T) {
	var code int
	_, err := requests.Get(nil, "https://httpbin.org/anything", requests.RequestOption{
		ClientOption: requests.ClientOption{
			ResultCallBack: func(ctx *requests.Response) error {
				if ctx.StatusCode() != 200 {
					return errors.New("resp.StatusCode!= 200")
				}
				code = ctx.StatusCode()
				return nil
			},
		},
	})
	if err != nil {
		t.Error(err)
	}
	if code != 200 {
		t.Error("code!= 200")
	}
}
