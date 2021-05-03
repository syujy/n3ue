package service

import (
	"errors"
	"fmt"
	"os"
	"os/signal"

	"n3ue/internal/config"
	"n3ue/internal/ike"
	"n3ue/internal/n3ue_exclusive"
	"n3ue/internal/projenv"

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
	n3ue.registration()
	n3ue.signalHandler()
	return nil
}

type N3UE struct {
	c       *config.Config
	runMode string
	n3ue_exclusive.N3UECommon
	// Services
	ikeService *ike.IKEService
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

func (e *N3UE) registration() {
	ikeSess := new(ike.Session)
	ikeSess.Init(e.N3UECommon, e.ikeService)
	taskIKE_SA_INIT := ike.NewTask()
	taskIKE_SA_INIT.PushFunc(ikeSess.IKE_SA_INIT)
	e.TM.NewTask(taskIKE_SA_INIT)
	s := taskIKE_SA_INIT.GetStatus()
	fmt.Printf("Task status: %d\n", s)
}
