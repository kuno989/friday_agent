package agent

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

func (s *Server) jobStartHandler(sha256 string, buff []byte) {
	client := &http.Client{}
	client.Timeout = time.Second * 20
	uri := s.Config.BrokerURI + s.Config.BrokerPort + "/api/jobStart/" + sha256
	body := bytes.NewBuffer(buff)
	req, err := http.NewRequest(http.MethodPut, uri, body)
	if err != nil {
		logrus.Fatalf("failed to request %v", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		logrus.Fatalf("failed to request %v", err)
	}
	defer resp.Body.Close()
	d, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatalf("failed to read response %v", err)
	}
	logrus.Infof("status code: %d, response: %s", resp.StatusCode, string(d))
}
