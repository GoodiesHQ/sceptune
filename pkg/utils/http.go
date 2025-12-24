package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func PostJson(ctx context.Context, client *http.Client, url string, headers map[string]string, reqObj, resObj any) (*http.Request, int, http.Header, []byte, error) {
	if client == nil {
		client = http.DefaultClient
	}

	reqBody, err := json.Marshal(reqObj)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, 0, nil, nil, err
	}

	if headers == nil {
		headers = make(map[string]string)
	}

	if _, ok := headers["Content-Type"]; !ok {
		req.Header.Set("Content-Type", "application/json")
	}

	if _, ok := headers["Accept"]; !ok {
		req.Header.Set("Accept", "application/json")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	res, err := client.Do(req)
	if err != nil {
		return req, 0, nil, nil, err
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return req, res.StatusCode, res.Header, nil, err
	}

	if res.StatusCode >= 200 && res.StatusCode <= 299 {
		if resObj != nil && len(resBytes) > 0 {
			if err := json.Unmarshal(resBytes, resObj); err != nil {
				return req, res.StatusCode, res.Header, resBytes, err
			}
		}
		return req, res.StatusCode, res.Header, resBytes, nil
	}

	return req, res.StatusCode, res.Header, resBytes, fmt.Errorf("unexpected status code %d", res.StatusCode)
}
