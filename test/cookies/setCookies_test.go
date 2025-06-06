package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"

	"github.com/wmm1996528/requestsgo"
)

func TestSetCookies(t *testing.T) {
	session, _ := requests.NewClient(context.TODO())

	//_, err := session.Get(context.TODO(), "http://httpbin.org/cookies/set?freeform=1111")
	//if err != nil {
	//	log.Panic(err)
	//}
	uri, _ := url.Parse("http://httpbin.org/cookies/set?freeform=1111")
	cookie := "a=b"
	cks := strings.Split(cookie, "; ")
	fmt.Println("lencks", len(cks))
	for _, ck := range cks {
		t := strings.Index(ck, "=")
		if t != -1 {
			session.SetCookies(uri, ck)
		}
		//fmt.Println(ck[:t], ck[t+1:], zhuanyi(ck[t+1:]))

	}

	resp, err := session.Get(context.TODO(), "http://httpbin.org/anything", requests.RequestOption{
		ClientOption: requests.ClientOption{
			RequestCallBack: func(ctx *requests.Response) error {
				if ctx.Request().Cookies() == nil {
					log.Panic("cookie is nil")
				}
				return nil
			},
		},
	})
	fmt.Println(resp.Text())
	if err != nil {
		log.Panic(err)
	}
}
