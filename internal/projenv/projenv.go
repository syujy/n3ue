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

	VarDir         = filepath.Join(Root, "var")
	VarRunDir      = filepath.Join(VarDir, "run")
	PidFile        = filepath.Join(VarRunDir, "pid")
	SockFile       = filepath.Join(VarRunDir, "sock")
	VarLogDir      = filepath.Join(VarDir, "log")
	DefaultLogFile = filepath.Join(VarLogDir, "n3ue.log")
)
