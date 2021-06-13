module n3ue

go 1.14

require (
	bitbucket.org/_syujy/ike v0.0.0-20210505140255-800d8b908788
	bitbucket.org/free5gc-team/UeauCommon v0.0.0-20201211040450-fc83e159de75
	bitbucket.org/free5gc-team/fsm v0.0.0-20210310053819-240603e3fb39
	bitbucket.org/free5gc-team/milenage v0.0.0-20201211040256-1f9245345719
	bitbucket.org/free5gc-team/nas v0.0.0-20210512024316-f575f796916e
	bitbucket.org/free5gc-team/ngap v0.0.0-20210414080844-063a8973125d
	bitbucket.org/free5gc-team/openapi v0.0.0-20210416060210-2f59856943b2
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/lestrrat-go/file-rotatelogs v2.4.0+incompatible
	github.com/lestrrat-go/strftime v1.0.4 // indirect
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli/v2 v2.3.0
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.0.0-20210330210617-4fbd30eecc44
	gopkg.in/yaml.v2 v2.4.0
)

replace bitbucket.org/_syujy/ike => ../ike
