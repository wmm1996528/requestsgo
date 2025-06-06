package main

import (
	"log"
	"testing"

	"github.com/gospider007/gson"
	"github.com/gospider007/tools"
	"github.com/wmm1996528/requestsgo"
)

func TestSendJsonWithMap(t *testing.T) {
	jsonBody := map[string]any{
		"name": "test",
	}
	resp, err := requests.Post(nil, "https://httpbin.org/anything", requests.RequestOption{
		Json: jsonBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := resp.Json()
	if err != nil {
		t.Fatal(err)
	}
	if jsonData.Get("headers.Content-Type").String() != "application/json" {
		t.Fatal("json data error")
	}
	bodyJson, err := gson.Decode(jsonBody)
	if err != nil {
		t.Fatal(err)
	}
	if bodyJson.String() != jsonData.Get("data").String() {
		t.Fatal("json data error")
	}
}
func TestSendJsonWithString(t *testing.T) {
	jsonBody := `{"name":"test"}`
	resp, err := requests.Post(nil, "https://httpbin.org/anything", requests.RequestOption{
		Json: jsonBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := resp.Json()
	if err != nil {
		t.Fatal(err)
	}
	if jsonData.Get("headers.Content-Type").String() != "application/json" {
		t.Fatal("json data error")
	}
	if jsonBody != jsonData.Get("data").String() {
		t.Fatal("json data error")
	}
}
func TestSendJsonWithStruct(t *testing.T) {
	jsonBody := struct{ Name string }{"test"}
	resp, err := requests.Post(nil, "https://httpbin.org/anything", requests.RequestOption{
		Json: jsonBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := resp.Json()
	if err != nil {
		t.Fatal(err)
	}
	if jsonData.Get("headers.Content-Type").String() != "application/json" {
		t.Fatal("json data error")
	}
	bodyJson, err := gson.Decode(jsonBody)
	if err != nil {
		t.Fatal(err)
	}
	if bodyJson.String() != jsonData.Get("data").String() {
		t.Fatal("json data error")
	}
}
func TestSendJsonWithGson(t *testing.T) {
	bodyJson, err := gson.Decode(struct{ Name string }{"test"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := requests.Post(nil, "https://httpbin.org/anything", requests.RequestOption{
		Json: bodyJson,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := resp.Json()
	if err != nil {
		t.Fatal(err)
	}
	if jsonData.Get("headers.Content-Type").String() != "application/json" {
		t.Fatal("json data error")
	}
	if bodyJson.String() != jsonData.Get("data").String() {
		t.Fatal("json data error")
	}
}
func TestSendJsonWithOrder(t *testing.T) {
	orderMap := requests.NewOrderData()
	orderMap.Add("age", "1")
	orderMap.Add("age4", "4")
	orderMap.Add("Name", "test")
	orderMap.Add("age2", "2")
	orderMap.Add("age3", []string{"22", "121"})

	bodyJson, err := gson.Encode(orderMap)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := requests.Post(nil, "https://httpbin.org/anything", requests.RequestOption{
		Json: orderMap,
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := resp.Json()
	if err != nil {
		t.Fatal(err)
	}
	if jsonData.Get("headers.Content-Type").String() != "application/json" {
		t.Fatal("json data error")
	}
	if tools.BytesToString(bodyJson) != jsonData.Get("data").String() {
		log.Print(jsonData.Get("data").String())
		t.Fatal("json data error")
	}
}

func TestSendJsonWithEmptiyMap(t *testing.T) {
	resp, err := requests.Post(nil, "https://httpbin.org/anything", requests.RequestOption{
		Form: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 {
		t.Fatal("status code error")
	}
}
