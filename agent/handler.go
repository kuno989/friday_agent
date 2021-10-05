package agent

import (
	"context"
	"encoding/json"
	"fmt"
	windows "github.com/elastic/go-windows"
	"github.com/kuno989/friday_agent/agent/schema"
	models "github.com/kuno989/friday_agent/agent/schema/model"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	queued       = iota
	processing   = iota
	finished     = iota
	vmProcessing = iota
)

func (s *Server) index(c echo.Context) error {
	return c.JSON(http.StatusOK, schema.Response{
		Message: "Success",
		Description: "Friday Agent 정상 작동 중",
	})
}

func (s *Server) system(c echo.Context) error {
	sys, err := windows.GetNativeSystemInfo()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, schema.Response{
			Message: "Error",
			Description: "파일 정보를 가져 올 수 없음",
		})
	}
	system := schema.System{}
	system.Platform = "Windows"
	system.Architecture = fmt.Sprintf("%s",sys.ProcessorArchitecture)
	system.Type = fmt.Sprintf("%s",sys.ProcessorType)
	system.NumberOfProcessors = sys.NumberOfProcessors
	return c.JSON(http.StatusOK, schema.Response{
		Message: "Success",
		Description: "Virtaulbox platform info",
		System: system,
	})
}

func (s *Server) malwareDownload(c echo.Context) error {
	var resp schema.ResponseObject
	logrus.Info("파일 다운로드 중")
	if err := c.Bind(&resp); err != nil {
		return err
	}
	var fileType string
	if resp.FileType == "pe" {
		fileType = ".exe"
	}
	filePath := filepath.Join("./", resp.Sha256 + fileType)
	file, err := os.Create(filePath)
	if err != nil {
		logrus.Errorf("failed creating file %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.minio.Download(ctx, resp.MinioObjectKey, file); err != nil {
		return c.JSON(http.StatusInternalServerError, schema.Response{
			Message: "Error",
			Description: "파일 다운로드 실패",
		})
	}
	file.Close()
	logrus.Info("파일 다운로드 완료")
	var StatusChanger = schema.StatusChanger{
		Sha256: resp.Sha256,
		MinioObjectKey: resp.MinioObjectKey,
		FileType: resp.FileType,
		Status: vmProcessing,
	}
	var buff []byte
	if buff, err = json.Marshal(StatusChanger); err != nil {
		logrus.Errorf("Failed to json marshall object: %v ", err)
	}
	s.jobStartHandler(resp, buff)
	return c.JSON(http.StatusOK, schema.Response{
		Message: "Success",
		Description: "Mal downloaded",
	})
}

func (s *Server) startAnalysis(c echo.Context) error {
	var resp schema.ResponseObject
	if err := c.Bind(&resp); err != nil {
		return err
	}
	var file string
	s.checkProcmon()

	if resp.FileType == "pe" {
		file = fmt.Sprintf("%s.exe",resp.Sha256)
	}
	logrus.Infof("%s 분석 시작", file)
	path := fmt.Sprintf("%s\\%s",s.Config.Volume,file)
	malwareName, pid := s.startMalware(file,path)
	logrus.Infof("%s 악성코드 실행 완료", file)
	s.processCapture()

	processCaptureTimer := time.NewTimer(time.Second * 15)
	go func() {
		<-processCaptureTimer.C
		s.terminateProcmon()
	}()

	pmltoCSVTimer := time.NewTimer(time.Second * 40)
	go func() {
		<-pmltoCSVTimer.C
		logrus.Info("")
		s.pmltoCSV()
	}()

	jsonConvertTimer := time.NewTimer(time.Second * 60)
	var data models.DBModel
	go func() {
		<-jsonConvertTimer.C
		logrus.Info("")
		s.ConvertCsvToJson(&data)
	}()

	jobEndTimer := time.NewTimer(time.Second * 70)
	go func() {
		<-jobEndTimer.C
		logrus.Info("분석 종료 요청 중")
		s.jobEndHandler(resp, &data)
	}()

	return c.JSON(http.StatusOK, schema.ResponsePid{
		MalwareName: malwareName,
		Pid: pid,
	})
}
