package logger

import (
	"io"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
)

type N3UELog struct {
	log    *logrus.Logger
	f      io.Writer
	format logrus.Formatter
}

func (l *N3UELog) Init(logFile string) error {
	writter, err := rotatelogs.New(
		logFile+".%Y%m%d",
		rotatelogs.WithLinkName(logFile),
		rotatelogs.ForceNewFile(),
	)
	if err != nil {
		return err
	}
	l.f = writter
	l.log = logrus.New()
	l.format = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	l.log.SetFormatter(l.format)
	l.log.AddHook(lfshook.NewHook(
		lfshook.WriterMap{
			logrus.TraceLevel: l.f,
			logrus.DebugLevel: l.f,
			logrus.InfoLevel:  l.f,
			logrus.WarnLevel:  l.f,
			logrus.ErrorLevel: l.f,
			logrus.FatalLevel: l.f,
			logrus.PanicLevel: l.f,
		},
		&logrus.TextFormatter{},
	))

	// Init logs with field

	return nil
}

func (l *N3UELog) SetLogLevel(level logrus.Level) {
	l.log.SetLevel(level)
}

func (l *N3UELog) SetReportCaller(set bool) {
	l.log.SetReportCaller(set)
}

func (l *N3UELog) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.log.WithFields(fields)
}
