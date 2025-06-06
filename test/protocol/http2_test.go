package main

import (
	"context"
	"log"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestHttp2(t *testing.T) {
	resp, err := requests.Get(context.TODO(), "https://httpbin.org/anything")
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode() != 200 {
		t.Error("resp.StatusCode2!= 200")
	}
	if resp.Proto() != "HTTP/2.0" {
		t.Error("resp.Proto!= HTTP/2.0")
	}
	log.Print(resp.Text())
	for range 3 {
		resp, err = requests.Get(context.TODO(), "https://mp.weixin.qq.com")
		if err != nil {
			t.Error(err)
		}
		if resp.StatusCode() != 200 {
			t.Error("resp.StatusCode!= 200")
		}
		log.Print(resp.Text())
		if resp.Proto() != "HTTP/2.0" {
			t.Error("resp.Proto!= HTTP/2.0")
		}
	}
	resp, err = requests.Post(context.TODO(), "https://mp.weixin.qq.com", requests.RequestOption{
		Body: "fasfasfsdfdssdsfasdfasdfsadfsdf对方是大翻身大翻身大翻身对方的身份",
		ClientOption: requests.ClientOption{
			ErrCallBack: func(ctx *requests.Response) error {
				log.Print(ctx.Err())
				return nil
			},
		},
	})
	if err != nil {
		t.Error(err)
	}
	log.Print(resp.Text())
	if resp.StatusCode() != 200 {
		t.Error("resp.StatusCode!= 200")
	}
	if resp.Proto() != "HTTP/2.0" {
		t.Error("resp.Proto!= HTTP/2.0")
	}
}
