package nas

import (
	"context"
	"github.com/syujy/n3ue/internal/task_manager"
)

var _ task_manager.Task = &task{}

type task struct {
	// Task Object
	status chan int
	cb     []func(*task) int
	// Parameters
	ctx context.Context
	// Context
}

func NewTask() *task {
	return &task{
		status: make(chan int),
		cb:     make([]func(*task) int, 0),
	}
}

func (t *task) Run() int {
	var s int
	for _, f := range t.cb {
		s = f(t)
		if s != task_manager.Success {
			break
		}
	}
	return s
}

func (t *task) GetStatus() int {
	return <-t.status
}

func (t *task) SetStatus(s int) {
	t.status <- s
}

func (t *task) PushFunc(f func(*task) int) {
	t.cb = append(t.cb, f)
}

func (t *task) PopFunc() {
	if len(t.cb) > 0 {
		t.cb = t.cb[:len(t.cb)-1]
	}
}
