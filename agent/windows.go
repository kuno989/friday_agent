//go:build windows
// +build windows

package agent

import (
	"fmt"
	"github.com/go-vgo/robotgo"
)

const (
	STATUS_INIT = 0x0001
	STATUS_RUNNING = 0x0002
	STATUS_COMPLETED = 0x0003
	STATUS_FAILED = 0x0004
)

func move() {
	robotgo.Move(100, 200)
	robotgo.MoveRelative(10, -200)

	// move the mouse to 100, 200
	robotgo.MoveMouse(100, 200)

	robotgo.Drag(10, 10)
	robotgo.Drag(20, 20, "right")
	//
	robotgo.DragSmooth(10, 10)
	robotgo.DragSmooth(100, 200, 1.0, 100.0)

	// smooth move the mouse to 100, 200
	robotgo.MoveSmooth(100, 200)
	robotgo.MoveMouseSmooth(100, 200, 1.0, 100.0)
	robotgo.MoveSmoothRelative(10, -100, 1.0, 30.0)

	for i := 0; i < 1080; i += 1000 {
		fmt.Println(i)
		robotgo.MoveMouse(800, i)
	}
}