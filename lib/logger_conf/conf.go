package logger_conf

import (
	"os"
)

var N3UELogDir string = "/var/log/n3ue/"

func init() {
	if _, err := os.Stat(N3UELogDir); os.IsNotExist(err) {
		err = os.Mkdir(N3UELogDir, 0775)
		if err != nil {
			panic("Create directory for logger failed. Exit.")
		}
	}
}
