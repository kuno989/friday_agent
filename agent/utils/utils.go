package utils

import (
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

func CMD(run bool, name string, arg ...string) {
	if run {
		cmd := exec.Command(name, arg...)
		cmd.Stdout = os.Stdout

		if err := cmd.Run(); err != nil {
			logrus.Errorf("%s 을 찾을 수 없습니다.", name)
		}
	}
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		logrus.Errorf("%s 을 찾을 수 없습니다.", name)
	}
}

func CheckApproveLists(list string) bool {
	approveLists := []string{
		"C:\\\\Program Files\\\\Windows Media Player\\\\wmpnetwk.exe",
		"C:\\\\Program Files\\\\Windows Media Player\\\\wmpnscfg.exe",
		"C:\\\\Windows\\\\Explorer.EXE",
		"C:\\\\Windows\\\\system32\\\\lsm.exe",
		"C:\\\\Users\\\\Administrator\\\\Desktop\\\\sandbox.exe",
		"C:\\\\procmon.exe",
		"C:\\\\Windows\\\\system32\\\\vssvc.exe",
		"C:\\\\Windows\\\\system32\\\\mobsync.exe",
		"C:\\\\Windows\\\\system32\\\\DllHost.exe",
	}
	for _, ls := range approveLists {
		if ls == list {
			return true
		}
	}
	return false
}
