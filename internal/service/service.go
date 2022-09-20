package service

import (
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/syujy/n3ue/internal/config"
	"github.com/syujy/n3ue/internal/ike"
	"github.com/syujy/n3ue/internal/n3ue_exclusive"
	"github.com/syujy/n3ue/internal/nas"
	"github.com/syujy/n3ue/internal/projenv"
	"github.com/syujy/n3ue/internal/sessInterface"
	"github.com/syujy/n3ue/internal/task_manager"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func Start(configPath string, runMode string) error {
	n3ue := new(N3UE)
	if err := n3ue.init(configPath, runMode); err != nil {
		return err
	}
	if err := n3ue.start(); err != nil {
		return err
	}
	n3ue.initSess()
	if s := n3ue.registration(); s == task_manager.Failed {
		return errors.New("Run registration failed")
	}
	if s := n3ue.pduSessionEstablishment(); s == task_manager.Failed {
		return errors.New("Run PDU session establishment failed")
	}
	n3ue.signalHandler()
	return nil
}

type N3UE struct {
	c       *config.Config
	runMode string
	n3ue_exclusive.N3UECommon
	// Log
	log *logrus.Entry
	// Services
	ikeService *ike.IKEService
	// Sessions
	ikeSess *ike.Session
	nasSess *nas.Session
}

func (e *N3UE) init(configPath string, runMode string) error {
	// Initialize - config
	// config
	var conf string
	if configPath != "" {
		conf = configPath
	} else {
		conf = projenv.DefaultConfigFile
	}
	e.c = new(config.Config)
	if err := e.c.ReadConfigFile(conf); err != nil {
		return err
	}
	// run mode
	e.runMode = runMode
	return nil
}

func (e *N3UE) start() error {
	if e.c == nil {
		return errors.New("Configuration not initialized.")
	}
	// Initialize - logger, context
	// context
	if err := e.InitCtx(e.c); err != nil {
		return err
	}

	// logger
	if err := e.InitLog(e.Ctx.Log.LogPath); err != nil {
		return err
	}

	// Set N3UE log as specified in context
	e.Log.SetLogLevel(e.Ctx.Log.DebugLevel)
	e.Log.SetReportCaller(e.Ctx.Log.ReportCaller)
	e.log = e.Log.WithFields(logrus.Fields{"component": "N3UE", "category": "UE"})

	// Task Manager
	if err := e.InitTaskManager(100, 20); err != nil {
		return err
	}

	// Execute services
	e.ikeService = new(ike.IKEService)
	e.ikeService.Init(e.N3UECommon)
	if err := e.ikeService.Run(); err != nil {
		return err
	}

	return nil
}

func (e *N3UE) signalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		unix.SIGHUP,
		unix.SIGINT,
		unix.SIGQUIT,
		unix.SIGTERM)

	for {
		sig := <-sigChan
		switch sig {
		case unix.SIGHUP:
			fmt.Println("Received SIGHUP") // temp
			e.reload()
		case unix.SIGINT:
			fmt.Println("Received SIGINT") // temp
			e.stop()
		case unix.SIGQUIT:
			fmt.Println("Received SIGQUIT") // temp
			e.stop()
		case unix.SIGTERM:
			fmt.Println("Received SIGTERM") // temp
			e.stop()
		}
	}

}

func (e *N3UE) stop() {
	// Stop NAS session
	if err := e.nasSess.SessionStopHard(); err != nil {
		e.log.Errorf("Delete NAS session failed: %+v", err)
	}
	// Stop IKE session
	if err := e.ikeSess.SessionStopHard(); err != nil {
		e.log.Errorf("Delete IKE session failed: %+v", err)
	}
	// Remove pid file
	if err := os.Remove(projenv.PidFile); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func (e *N3UE) reload() {
	fmt.Println("Handle SIGHUP") // temp
}

func (e *N3UE) initSess() {
	si1 := make(chan *sessInterface.SessInt, 10)
	si2 := make(chan *sessInterface.SessInt, 10)
	e.ikeSess = new(ike.Session)
	e.ikeSess.Init(e.N3UECommon, e.ikeService, si1, si2)
	e.nasSess = new(nas.Session)
	e.nasSess.Init(e.N3UECommon, si2, si1)
}

func (e *N3UE) registration() int {
	ikeTask := ike.NewTask()
	ikeTask.PushFunc(e.ikeSess.IKE_SA_INIT)
	ikeTask.PushFunc(e.ikeSess.IKE_AUTH)
	nasTask := nas.NewTask()
	nasTask.PushFunc(e.nasSess.RegistrationRequest)
	e.TM.NewTask(ikeTask)
	e.TM.NewTask(nasTask)
	return nasTask.GetStatus()
}

func (e *N3UE) pduSessionEstablishment() int {
	nasTask := nas.NewTask()
	nasTask.PushFunc(e.nasSess.PDUSessionEstablishmentRequest)
	e.TM.NewTask(nasTask)
	return nasTask.GetStatus()
}
