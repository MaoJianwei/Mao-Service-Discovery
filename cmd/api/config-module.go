package MaoApi

var (
	ConfigModuleRegisterName = "api-config-module"
)

type ConfigModule interface {
	GetConfig(path string) (object interface{}, errCode int)
	GetSecConfig(path string) (object interface{}, errCode int)
	PutConfig(path string, data interface{}) (success bool, errCode int)
	PutSecConfig(path string, data interface{}) (success bool, errCode int)
	RegisterKeyUpdateListener(listener *chan int)
}

