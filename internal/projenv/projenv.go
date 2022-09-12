package projenv

import (
	"path/filepath"
	"runtime"
)

var (
	_, b, _, _ = runtime.Caller(0)
	Root       = filepath.Join(filepath.Dir(b), "../..")

	EtcDir            = filepath.Join(Root, "etc")
	DefaultConfigFile = filepath.Join(EtcDir, "n3ueconf.yml")
	NASSQNFile        = filepath.Join(EtcDir, "sqn")

	VarDir         = filepath.Join(Root, "var")
	VarLogDir      = filepath.Join(VarDir, "log")
	DefaultLogFile = filepath.Join(VarLogDir, "n3ue.log")
	VarRunDir      = filepath.Join(VarDir, "run")
	PidFile        = filepath.Join(VarRunDir, "pid")
	SockFile       = filepath.Join(VarRunDir, "sock")
)
