// HTTP client for Fortigate API using token authentication
//
// Copyright (C) 2020  Christian Svensson
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
	"bytes"
)

type FortiManagerClient struct {
	tgt url.URL
	res string
	hc  HTTPClient
	ctx context.Context
	username string
	password string
}

type FMGResponse struct {
	Method string `json:"method"`
	Result []FMGResult `json:"result"`
	ID int `json:"id"`
}

type FMGResult struct {
	Data []FMGData `json:"data"`
	Status FMGStatus `json:"status"`
	URL string `json:"url"`
}

type FMGData struct {
	Response json.RawMessage `json:"response"`
	Target string `json:"target"`
}

type FMGStatus struct {
	Code int `json:"code"`
	Message string `json:"message"`
}

func (c *FortiManagerClient) getSession() (string, error) {
	var ses []byte
	
	rpc_url := c.tgt.String() + "/jsonrpc"
	ses, err := ioutil.ReadFile("session")
	if err != nil {
		// Request new session token from the FortiManager
		reqBody, err := json.Marshal(map[string]interface{}{
			"method": "exec",
			"params": []map[string]interface{}{
				map[string]interface{}{
					"data": map[string]string{
						"passwd": c.password,
						"user": c.username,
					},
					"url": "/sys/login/user",
				},
			},
		})

		if err != nil {
			return "", err
		}

		resp, err := http.Post(rpc_url, "application/json", bytes.NewBuffer(reqBody))

		if err != nil {
			return "", err
		}

		defer resp.Body.Close()

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		session := result["session"]

		err = ioutil.WriteFile("session", []byte(session), 0600)
	}

	return string(ses), err
}

func (c *FortiManagerClient) newQuery(resource string) (*http.Request, error) {
	ses, err := c.getSession()

	if err != nil {
		return nil, err
	}

	var res_url string
	rpc_url := c.tgt.String() + "/jsonrpc"
	path, err := url.Parse(resource)

	if err != nil {
		return nil, err
	}

	if path.ForceQuery {
		res_url = path.Path + "?" + path.RawQuery
	} else {
		res_url = path.Path
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"method": "exec",
		"params": []map[string]interface{}{
			map[string]interface{}{
				"data": map[string]interface{}{
					"action": "get",
					"payload": map[string]string{},
					"resource": res_url,
					"target": []string{
						c.res,
					},
				},
				"url": "/sys/proxy/json",
			},
		},
		"session": ses,
	})

	http.DefaultTransport.(*http.Transport).TLSHandshakeTimeout = time.Duration(*tlstimeout) * time.Second
	r, err := http.NewRequestWithContext(c.ctx, "POST", rpc_url, bytes.NewBuffer(reqBody))
	
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	
	return r, nil
}

func (c *FortiManagerClient) Query(path string, query string, obj interface{}) error {
	u := c.tgt
	u.Path = path
	u.RawQuery = query

	req, err := c.newQuery(u.String())
	if err != nil {
		return err
	}

	req = req.WithContext(c.ctx)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Response code was %d, expected 200", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	response := FMGResponse{}
	err = json.Unmarshal(b, &response)

	if err != nil {
		return err
	}

	err = json.Unmarshal(response.Result[0].Data[0].Response, &obj)

	if err != nil {
		return err
	}

	return nil
}

func (c *FortiManagerClient) String() string {
	return c.tgt.String()
}

func newFortiManagerClient(ctx context.Context, tgt url.URL, res string, hc HTTPClient, username string, password string) (*FortiManagerClient, error) {
	return &FortiManagerClient{tgt, res, hc, ctx, username, password}, nil
}
