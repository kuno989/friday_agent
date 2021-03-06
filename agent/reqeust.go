package agent

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/kuno989/friday_agent/agent/schema"
	models "github.com/kuno989/friday_agent/agent/schema/model"
	"github.com/kuno989/friday_agent/agent/utils"
	"github.com/sirupsen/logrus"
	"github.com/vova616/screenshot"
	"image/jpeg"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	imageSave = "C:\\Users\\kuno\\Downloads"
	procmon = "C:\\procmon.exe"
	pmc = "C:\\ProcmonConfiguration.pmc"
	pml = "C:\\Users\\kuno\\Downloads\\kuno_sandbox.pml"
	csvData = "C:\\Users\\kuno\\Downloads\\kuno_sandbox.csv"
	jsonData = "C:\\Users\\kuno\\Downloads\\kuno_sandbox.json"
)

func (s *Server) jobStartHandler(data schema.ResponseObject, buff []byte) {
	client := &http.Client{}
	client.Timeout = time.Second * 20
	uri := s.Config.BrokerURI + s.Config.BrokerPort + "/api/jobStart/" + data.Sha256
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
	//d, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	logrus.Fatalf("failed to read response %v", err)
	//}
	//logrus.Infof("status code: %d, response: %s", resp.StatusCode, string(d))
}

func (s *Server) jobEndHandler(data schema.ResponseObject, result *models.DBModel) {
	client := &http.Client{}
	client.Timeout = time.Second * 20

	buff, err := json.Marshal(result)
	if err != nil {
		logrus.Errorf("Failed to json marshall object: %v ", err)
	}
	body := bytes.NewBuffer(buff)

	uri := s.Config.BrokerURI + s.Config.BrokerPort + "/api/jobEnd/" + data.Sha256
	resp, err := http.Post(uri,"application/json", body)
	if err != nil {
		logrus.Fatalf("failed to request %v", err)
	}
	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	defer resp.Body.Close()
}

func (s *Server) checkProcmon() {
	if _, err := os.Stat(procmon); os.IsNotExist(err) {
		logrus.Error("Procmon.exe ??? ?????? ??? ????????????.")
	}
}

func (s *Server) processCapture() {
	logrus.Infof("???????????? ?????? ???")
	//v := []string{"cmd.exe", "/C", "start", procmon, "/BackingFile", pml, "/Quiet", "/Minimized","/LoadConfig", pmc}
	v := []string{"cmd.exe", "/C", "start", procmon, "/BackingFile", pml, "/Quiet", "/Minimized"}
	cmd := exec.Command(v[0], v[:]...)
	if err := cmd.Run(); err != nil {
		logrus.Errorf("%s ??? ?????? ??? ????????????.", procmon)
	}
}

func (s *Server) pmltoCSV() {
	defer logrus.Infof("????????? ?????? ??????")
	//v := []string{"cmd.exe", "/C", "start", procmon, "/OpenLog", pml, "/SaveApplyFilter", "/saveas", csvData, "/LoadConfig", pmc}
	v := []string{"cmd.exe", "/C", "start", procmon, "/OpenLog", pml, "/SaveApplyFilter", "/saveas", csvData}
	cmd := exec.Command(v[0], v[:]...)
	if err := cmd.Run(); err != nil {
		logrus.Errorf("%s ??? ?????? ??? ????????????.", procmon)
	}
}

func (s *Server) captureImage(sha256 string, num int) string {
	img, err := screenshot.CaptureScreen()
	defer logrus.Info("????????? ?????? ??????")
	if err != nil {
		logrus.Errorf("????????? ?????? ??????")
	}
	filePath := fmt.Sprintf("%s\\%s-%d.jpeg",imageSave,sha256,num)
	f, err := os.Create(filePath)
	defer f.Close()
	if err != nil {
		logrus.Errorf("????????? ?????? ??????")
	}
	err = jpeg.Encode(f, img, &jpeg.Options{95})
	if err != nil {
		logrus.Errorf("????????? ?????? ??????")
	}
	return filePath
}

func (s *Server) terminateProcmon() {
	defer logrus.Info("?????? ??????")
	v := []string{"cmd.exe", "/C", "start", procmon, "/Terminate"}
	cmd := exec.Command(v[0], v[:]...)
	if err := cmd.Run(); err != nil {
		logrus.Errorf("%s ??? ?????? ??? ????????????.", procmon)
	}
}


func (s *Server) startMalware(path string) {
	v := []string{"cmd.exe", "/C", "start", path}
	cmd := exec.Command(v[0], v[:]...)
	if err := cmd.Run(); err != nil {
		logrus.Errorf("%s ??? ?????? ??? ????????????.", path)
	}
}

func (s *Server) ConvertCsvToJson(data *models.DBModel) {
	defer log.Println("????????? ?????? ??????")

	var processCreate models.ProcessCreate
	var createFile models.CreateFile
	var deleteFile models.DeleteFile
	var readFile models.ReadFile

	var setRegValue models.SetRegValue
	var deleteRegValue models.DeleteRegValue
	var deleteRegKey models.DeleteRegKey
	var renameFile models.RenameFile
	var createRegKey models.RegCreateKey
	var openregKey models.OpenRegKey
	var getregKey models.GetRegKey

	var udpStuct models.UDP
	var tcpStuct models.TCP

	csvFile, err := os.Open(csvData)
	if err != nil {
		log.Println("[X] csv to json ?????? ??? ?????? ??????", err)
	}
	defer csvFile.Close()

	r := csv.NewReader(bufio.NewReader((csvFile)))
	r.LazyQuotes = true

	records, err := r.ReadAll()
	if err != nil {
		log.Println("[X] csv ??? ?????? ?????? ?????? ??????", err)
	}
	for i, rec := range records {
		if i > 0 {
			//replaceImagePath := strings.Replace(rec[8], "\\", "\\\\", -1)
			notApprove := utils.CheckApproveLists(rec)
			if !notApprove {
				switch rec[3] {
				case "Process Create":
					if rec[5] == "SUCCESS" {
						cmdLine := strings.Split(rec[6], "Command line: ")[1]
						childPID := strings.Split(strings.Split(rec[6], "PID: ")[1], ",")[0]
						processCreate.PID = rec[2]
						processCreate.ProcessName = rec[1]
						processCreate.Operation = cmdLine
						processCreate.ProcessPath = rec[8]
						processCreate.ChildPID = childPID

						data.ProcessCreate = append(data.ProcessCreate, processCreate)
					}

				case "CreateFile":
					if rec[5] == "SUCCESS" {
						c_path := rec[4]
						createFile.PID = rec[2]
						createFile.ProcessName = rec[1]
						createFile.ProcessPath = rec[8]
						createFile.CreatePath = c_path

						data.CreateFile = append(data.CreateFile, createFile)
					}

				case "ReadFile":
					readFile.PID = rec[2]
					readFile.ProcessName = rec[1]
					readFile.ProcessPath = rec[4]

					data.ReadFile = append(data.ReadFile, readFile)

				case "SetDispositionInformationFile":
					if rec[5] == "SUCCESS" {
						c_path := rec[4]
						deleteFile.PID = rec[2]
						deleteFile.ProcessName = rec[1]
						deleteFile.ProcessPath = rec[8]
						deleteFile.DeletePath = c_path

						data.DeleteFile = append(data.DeleteFile, deleteFile)
					}

				case "SetRenameInformationFile":
					from_file := rec[4]
					to_file := strings.Split(rec[6], "FileName: ")[1]
					renameFile.PID = rec[2]
					renameFile.ProcessName = rec[1]
					renameFile.ProcessPath = rec[8]
					renameFile.OriginName = from_file
					renameFile.ChangeName = to_file

					data.RenameFile = append(data.RenameFile, renameFile)

				case "RegCreateKey":
					if rec[5] == "SUCCESS" {
						createRegKey.PID = rec[2]
						createRegKey.ProcessName = rec[1]
						createRegKey.Key = rec[4]

						data.RegCreateKey = append(data.RegCreateKey, createRegKey)
					}

				case "RegOpenKey":
					if rec[5] == "SUCCESS" {
						openregKey.PID = rec[2]
						openregKey.ProcessName = rec[1]
						openregKey.Key = rec[4]

						data.OpenRegKey = append(data.OpenRegKey, openregKey)
					}

				case "RegQueryValue":
					if rec[5] == "SUCCESS" {
						getregKey.PID = rec[2]
						getregKey.ProcessName = rec[1]
						getregKey.Key = rec[4]

						data.GetRegKey = append(data.GetRegKey, getregKey)
					}
				case "RegSetValue":
					if rec[5] == "SUCCESS" {
						setRegValue.PID = rec[2]
						setRegValue.ProcessName = rec[1]
						setRegValue.Value = rec[4]

						data.SetRegValue = append(data.SetRegValue, setRegValue)
					}

				case "RegDeleteValue":
					deleteRegValue.PID = rec[2]
					deleteRegValue.ProcessName = rec[1]
					deleteRegValue.ProcessPath = rec[8]
					deleteRegValue.RegValue = rec[4]

					data.DeleteRegValue = append(data.DeleteRegValue, deleteRegValue)

				case "RegDeleteKey":
					deleteRegKey.PID = rec[2]
					deleteRegKey.ProcessName = rec[1]
					deleteRegKey.ProcessPath = rec[8]
					deleteRegKey.RegKey = rec[4]

					data.DeleteRegKey = append(data.DeleteRegKey, deleteRegKey)

				case "UDP Send":
					if rec[5] == "SUCCESS" {
						server := strings.Split(rec[4], "-> ")[1]
						udpStuct.PID = rec[2]
						udpStuct.ProcessName = rec[1]
						udpStuct.Action = "Send"
						udpStuct.Server = server

						data.UDP = append(data.UDP, udpStuct)
					}

				case "UDP Receive":
					if rec[5] == "SUCCESS" {
						server := strings.Split(rec[4], "-> ")[1]
						udpStuct.PID = rec[2]
						udpStuct.ProcessName = rec[1]
						udpStuct.Action = "Send"
						udpStuct.Server = server

						data.UDP = append(data.UDP, udpStuct)
					}

				case "TCP Send":
					if rec[5] == "SUCCESS" {
						server := strings.Split(rec[4], "-> ")[1]
						tcpStuct.PID = rec[2]
						tcpStuct.ProcessName = rec[1]
						tcpStuct.Action = "Send"
						tcpStuct.Server = server

						data.TCP = append(data.TCP, tcpStuct)
					}

				case "TCP Receive":
					if rec[5] == "SUCCESS" {
						server := strings.Split(rec[4], "-> ")[1]
						tcpStuct.PID = rec[2]
						tcpStuct.ProcessName = rec[1]
						tcpStuct.Action = "Receive"
						tcpStuct.Server = server

						data.TCP = append(data.TCP, tcpStuct)
					}
				}
			}
		}
	}

}