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
	filePath := fmt.Sprintf("%s\\%s%s",s.Config.Volume,resp.Sha256,fileType)
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
	s.processCapture()
	time.Sleep(time.Second * 5)

	var imageCapture []string
	var objectKeys []string

	path := fmt.Sprintf("%s\\%s",s.Config.Volume,file)

	processCaptureinit := time.NewTimer(time.Second * 10)
	go func() {
		<-processCaptureinit.C
		imagePath := s.captureImage(resp.Sha256, 1)
		imageCapture = append(imageCapture, imagePath)
	}()

	s.startMalware(path)
	logrus.Infof("%s 악성코드 실행 완료", file)

	processCaptureTimer := time.NewTimer(time.Second * 20)
	go func() {
		<-processCaptureTimer.C
		imagePath := s.captureImage(resp.Sha256, 2)
		imageCapture = append(imageCapture, imagePath)
		s.terminateProcmon()
	}()

	pmltoCSVTimer := time.NewTimer(time.Second * 45)
	go func() {
		<-pmltoCSVTimer.C
		imagePath := s.captureImage(resp.Sha256, 3)
		imageCapture = append(imageCapture, imagePath)
		s.pmltoCSV()
	}()

	jsonConvertTimer := time.NewTimer(time.Second * 65)
	var data models.DBModel
	data.MalName = file
	go func() {
		<-jsonConvertTimer.C
		imagePath := s.captureImage(resp.Sha256, 4)
		imageCapture = append(imageCapture, imagePath)
		s.ConvertCsvToJson(&data)
	}()

	jobEndTimer := time.NewTimer(time.Second * 75)
	go func() {
		<-jobEndTimer.C
		imagePath := s.captureImage(resp.Sha256, 5)
		imageCapture = append(imageCapture, imagePath)
		logrus.Info("분석 종료 요청 중")
		data.ScreenShots = imageCapture
		ctx := context.Background()
		for _, screenshot := range imageCapture {
			uploadinfo, err := s.minio.Upload(ctx, screenshot)
			if err != nil {
				logrus.Errorf("minio error: %v", err)
			}
			objectKeys = append(objectKeys, uploadinfo.Key)
		}
		logrus.Info("스크린샷 업로드 완료")
		data.ScreenShots = objectKeys
		s.jobEndHandler(resp, &data)
	}()

	return c.JSON(http.StatusOK, schema.Response{
		Message: "Success",
		Description: "작업 요청 완료",
	})
}
