package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"n3ue/internal/projenv"
	"n3ue/internal/service"

	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func main() {
	n3ue := &cli.App{
		Name:  "N3UE",
		Usage: "A simulative UE that has non-3GPP access ability",
		Commands: []*cli.Command{
			{
				Name:        "start",
				Usage:       "Start N3UE",
				Description: "Start will start the program",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "daemon",
						Aliases: []string{"d"},
						Usage:   "Run as a daemon",
					},
					&cli.StringFlag{
						Name:     "mode",
						Aliases:  []string{"m"},
						Usage:    "Set runing mode `MODE`. MODE can be either 'ue' or 'rg'(without quote).",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Usage:   "Specify configuration file `path`.",
					},
				},
				Action: runStartCmd,
			},
			{
				Name:        "stop",
				Usage:       "Stop N3UE",
				Description: "Stop will stop the program",
				Action:      runStopCmd,
			},
			{
				Name:        "reload",
				Usage:       "Reload N3UE",
				Description: "Reload will reload the program",
				Action:      runReloadCmd,
			},
		},
		Version: "v1.0.0",
	}

	if err := n3ue.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runStartCmd(c *cli.Context) error {
	if c.Bool("daemon") {
		var newArgs []string
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "-d") || strings.HasPrefix(arg, "--daemon") {
				continue
			}
			newArgs = append(newArgs, arg)
		}
		cmd := exec.Command(newArgs[0], newArgs[1:]...)
		if err := cmd.Start(); err != nil {
			return err
		}
	} else {
		// If dir not exists, create it
		if _, err := os.Stat(projenv.VarRunDir); os.IsNotExist(err) {
			if err = os.MkdirAll(projenv.VarRunDir, 0o775); err != nil {
				return err
			}
		}
		if _, err := os.Stat(projenv.VarLogDir); os.IsNotExist(err) {
			if err = os.MkdirAll(projenv.VarLogDir, 0o775); err != nil {
				return err
			}
		}
		// Check if process running
		if proc, err := isRunning(); err != nil {
			if !os.IsNotExist(err) { // IsExist() check the error "already exist"
				return err
			}
		} else {
			if proc != nil {
				return errors.New("Process running!!")
			}
		}
		// Write pid
		pid := fmt.Sprintf("%d", os.Getpid())
		if err := ioutil.WriteFile(projenv.PidFile, []byte(pid), 0o644); err != nil {
			return err
		}
		// Run
		if err := service.Start(c.String("config"), c.String("mode")); err != nil {
			return err
		}
	}
	return nil
}

func runStopCmd(c *cli.Context) error {
	// Check if the process is running
	proc, err := isRunning()
	if err != nil {
		return err
	} else {
		if proc == nil {
			return errors.New("No such process.")
		}
	}
	// Send SIGTERM
	if err = proc.Signal(unix.SIGTERM); err != nil {
		return err
	}
	return nil
}

func runReloadCmd(c *cli.Context) error {
	// Check if the process is running
	proc, err := isRunning()
	if err != nil {
		return err
	} else {
		if proc == nil {
			return errors.New("No such process.")
		}
	}
	// Send SIGHUP
	if err = proc.Signal(unix.SIGHUP); err != nil {
		return err
	}
	return nil
}

func isRunning() (*os.Process, error) {
	pid, err := getPid()
	if err != nil {
		return nil, err
	}
	proc, _ := os.FindProcess(pid) // Always succeeds
	err = proc.Signal(unix.Signal(0))
	if err != nil {
		if os.IsPermission(err) {
			return proc, err
		} else {
			return nil, nil
		}
	} else {
		return proc, nil
	}
}
func getPid() (int, error) {
	var (
		content []byte
		err     error
		pid     int
	)

	content, err = ioutil.ReadFile(projenv.PidFile)
	if err != nil {
		return 0, err
	}
	pid, err = strconv.Atoi(string(content))
	if err != nil {
		return 0, err
	}
	return pid, nil
}
