module n3ue

go 1.14

require (
	bitbucket.org/_syujy/ike v0.0.0-20210421080347-07163b4d28db
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/lestrrat-go/strftime v1.0.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
	gopkg.in/yaml.v2 v2.3.0
)

replace bitbucket.org/_syujy/ike => ../ike
