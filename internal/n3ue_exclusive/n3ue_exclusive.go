package n3ue_exclusive

import (
	"errors"
	"n3ue/internal/config"
	"n3ue/internal/context"
	"n3ue/internal/logger"
	"n3ue/internal/task_manager"
)

type N3UECommon struct {
	Log *logger.N3UELog
	Ctx *context.N3UEContext
	TM  *task_manager.Task_manager
}

func (e *N3UECommon) InitLog(logPath string) error {
	if e.Log != nil {
		return errors.New("Log exists.")
	}
	e.Log = new(logger.N3UELog)
	if err := e.Log.Init(logPath); err != nil {
		return err
	}
	return nil
}

func (e *N3UECommon) InitCtx(c *config.Config) error {
	if e.Ctx != nil {
		return errors.New("Ctx exists.")
	}
	e.Ctx = new(context.N3UEContext)
	if err := e.Ctx.Init(c); err != nil {
		return err
	}
	return nil
}

func (e *N3UECommon) InitTaskManager(queueLen, workerNumber int) error {
	if e.TM != nil {
		return errors.New("TM exists.")
	}
	e.TM = new(task_manager.Task_manager)
	e.TM.Init(queueLen, workerNumber)
	e.TM.Run()
	return nil
}
