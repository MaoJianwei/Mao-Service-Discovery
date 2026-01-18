package MaoApi

import "time"

var (
	IcmpKaModuleRegisterName = "api-icmp-ka-module"
)

const (
	ICMP_CONFIG_KEY_ADDRESS      = "address"
	ICMP_CONFIG_KEY_SERVICE_NAME = "serviceName"
)

type MaoIcmpServiceIdentifier struct {
	ServiceIPv4v6 string `yaml:"address"` // Attention, this value MUST be modified simultaneously with ICMP_CONFIG_KEY_ADDRESS.
	ServiceName string `yaml:"serviceName"` // Attention, this value MUST be modified simultaneously with ICMP_CONFIG_KEY_SERVICE_NAME.
}

type MaoIcmpService struct {
	Address string
	ServiceName string

	Alive    bool
	LastSeen time.Time

	DetectCount uint64
	ReportCount uint64

	RttDuration          time.Duration
	RttOutboundTimestamp time.Time
}

type IcmpKaModule interface {
	AddService(service *MaoIcmpServiceIdentifier)
	DelService(serviceIPv4v6 string)
	GetServices() []*MaoIcmpService
}
