package task_manager

import (
	"sync"
)

type Task_manager struct {
	queueLength      int
	workerNumber     int
	taskQueue        chan Task
	availableWorkers chan *worker
}

type Task interface {
	Run() int
	SetStatus(int)
	GetStatus() int
}

const (
	Success    = 0
	Failed     = 1
	NoResource = 2
)

type worker struct {
	task    Task
	trigger sync.Mutex
}

func (tm *Task_manager) Init(queueLen, workerNumber int) {
	tm.queueLength = queueLen
	tm.workerNumber = workerNumber
	tm.taskQueue = make(chan Task, queueLen)
	tm.availableWorkers = make(chan *worker, workerNumber)
}

func (tm *Task_manager) Run() {
	for i := 0; i < tm.workerNumber; i += 1 {
		w := new(worker)
		w.trigger.Lock()
		go w.Run(tm.availableWorkers)
		tm.availableWorkers <- w
	}
	go tm.dispatchTask()
}

func (tm *Task_manager) NewTask(task Task) {
	tm.taskQueue <- task
}

func (tm *Task_manager) dispatchTask() {
	for {
		task := <-tm.taskQueue

		// worker, if no available, report NoResource
		select {
		case w := <-tm.availableWorkers:
			w.task = task
			w.trigger.Unlock()
		default:
			task.SetStatus(NoResource)
		}
	}
}

func (w *worker) Run(availableWorkers chan *worker) {
	for {
		w.trigger.Lock()
		w.task.SetStatus(w.task.Run())
		availableWorkers <- w
	}
}
