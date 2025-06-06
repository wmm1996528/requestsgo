package main

import (
	"context"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestRedirectCallBack(t *testing.T) {
	response, err := requests.Get(context.TODO(), "http://www.baidu.com", requests.RequestOption{
		ClientOption: requests.ClientOption{
			RequestCallBack: func(ctx *requests.Response) error {
				if ctx.Response() != nil {
					return requests.ErrUseLastResponse
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Error(err)
	}
	if response.StatusCode() != 302 {
		t.Error("redirect failed")
	}
}
