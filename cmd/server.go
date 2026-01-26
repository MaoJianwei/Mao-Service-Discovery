package branch

import (
	"MaoServerDiscovery/cmd/api"
	"MaoServerDiscovery/cmd/lib/AuxDataProcessor"
	config "MaoServerDiscovery/cmd/lib/Config"
	"MaoServerDiscovery/cmd/lib/Email"
	"MaoServerDiscovery/cmd/lib/GrpcKa"
	icmpKa "MaoServerDiscovery/cmd/lib/IcmpKa"
	"MaoServerDiscovery/cmd/lib/InfluxDB"
	"MaoServerDiscovery/cmd/lib/MaoCommon"
	"MaoServerDiscovery/cmd/lib/Restful"
	"MaoServerDiscovery/cmd/lib/Soap"
	MaoDatabase "MaoServerDiscovery/incubator/Database"
	"MaoServerDiscovery/incubator/MaoCloudMonitor"
	"MaoServerDiscovery/incubator/OnosTopoShow"
	"MaoServerDiscovery/util"
	parent "MaoServerDiscovery/util"
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
	"time"
)

const (
	s_MODULE_NAME = "General-Server"
)

//var (
// serviceAlive []*MaoApi.GrpcServiceNode // Mao: Deprecated, 2022.07.08.
//)

/**
Mao: Deprecated, 2022.07.08.
Using grpcModule.GetServiceInfo() and check service.Alive instead.

func updateServerAlive(refresh_interval uint32) {
	for {
		time.Sleep(time.Duration(refresh_interval) * time.Millisecond)

		grpcModule := MaoCommon.ServiceRegistryGetGrpcKaModule()
		if grpcModule == nil {
			util.MaoLogM(util.WARN, s_MODULE_NAME, "Fail to get GrpcKaModule")
			continue
		}
		serviceInfo := grpcModule.GetServiceInfo()

		serviceAliveTmp := make([]*MaoApi.GrpcServiceNode, 0)
		for _, s := range serviceInfo {
			if time.Now().Sub(s.LocalLastSeen) < 5 * time.Second {
				serviceAliveTmp = append(serviceAliveTmp, s)
			}
		}

		sort.Slice(serviceAliveTmp, func(i, j int) bool {
			return serviceAliveTmp[i].Hostname < serviceAliveTmp[j].Hostname
		})

		serviceAlive = serviceAliveTmp
	}
}
*/

func getIcmpServices() []*MaoApi.MaoIcmpService {
	icmpModule := MaoCommon.ServiceRegistryGetIcmpKaModule()
	if icmpModule == nil {
		util.MaoLogM(util.WARN, s_MODULE_NAME, "Fail to get IcmpKaModule")
		return make([]*MaoApi.MaoIcmpService, 0)
	}
	return icmpModule.GetServices()
}

func getGrpcServices() []*MaoApi.GrpcServiceNode {
	grpcModule := MaoCommon.ServiceRegistryGetGrpcKaModule()
	if grpcModule == nil {
		util.MaoLogM(util.WARN, s_MODULE_NAME, "Fail to get GrpcKaModule")
		return make([]*MaoApi.GrpcServiceNode, 0)
	}
	return grpcModule.GetServiceInfo()
}

func traceServicesForTopologyShow() {
	for {
		time.Sleep(3 * time.Second)

		topoModule := MaoCommon.ServiceRegistryGetTopoModule()
		if topoModule == nil {
			util.MaoLogM(util.WARN, s_MODULE_NAME, "Fail to get TopoModule")
			continue
		}

		icmpService := getIcmpServices()
		for _, s := range icmpService {
			event := &MaoApi.TopoEvent{
				EventType:   0,
				EventSource: MaoApi.SOURCE_ICMP,
				ServiceName: s.Address,
				Timestamp:   s.LastSeen,
			}

			if s.Alive {
				event.EventType = MaoApi.SERVICE_UP
			} else {
				event.EventType = MaoApi.SERVICE_DOWN
			}

			topoModule.SendEvent(event)
		}

		grpcService := getGrpcServices()
		for _, s := range grpcService {
			event := &MaoApi.TopoEvent{
				EventType:   0,
				EventSource: MaoApi.SOURCE_GRPC,
				ServiceName: s.Hostname,
				Timestamp:   s.LocalLastSeen,
			}

			if s.Alive {
				event.EventType = MaoApi.SERVICE_UP
			} else {
				event.EventType = MaoApi.SERVICE_DOWN
			}

			topoModule.SendEvent(event)
		}
	}
}

func getGrpcAliveService() []*MaoApi.GrpcServiceNode {
	serviceAliveTmp := make([]*MaoApi.GrpcServiceNode, 0)

	grpcModule := MaoCommon.ServiceRegistryGetGrpcKaModule()
	if grpcModule == nil {
		util.MaoLogM(util.WARN, s_MODULE_NAME, "Fail to get GrpcKaModule")
		return serviceAliveTmp
	}

	serviceInfo := grpcModule.GetServiceInfo()
	for _, s := range serviceInfo {
		if s.Alive {
			serviceAliveTmp = append(serviceAliveTmp, s)
		}
	}

	return serviceAliveTmp
}

func startCliOutput(cli_dump_interval uint32) {
	count := 1
	for {
		services := getGrpcAliveService()

		dump := ""
		for _, s := range services {
			dump = fmt.Sprintf("%s%s => %s - %s\n", dump, s.Hostname, s.LocalLastSeen, s.Ips)
		}
		util.MaoLogM(util.INFO, s_MODULE_NAME, "========== %d ==========\n%s", count, dump)

		count++
		time.Sleep(time.Duration(cli_dump_interval) * time.Millisecond)
	}
}

/**
Mao: Deprecated, 2022.07.08.
Deprecated "/json" and "/plain", use "/" and "/showMergeServiceIP" instead.

func showServers(c *gin.Context) {
	serverTmp := serviceAlive
	c.IndentedJSON(200, serverTmp)
}
func showServerPlain(c *gin.Context) {
	serverTmp := serviceAlive

	dump := "<html><meta http-equiv=\"refresh\" content=\"1\"><title>Mao Service Discovery</title><body>"
	for _, s := range serverTmp {
		dump = fmt.Sprintf("%s%s => %s - %s %s<br/>", dump, s.Hostname, s.LocalLastSeen, s.Ips, s.OtherData)
	}
	dump += "</body></html>"
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(200, dump)
}
*/

func showMergeServer(c *gin.Context) {
	c.HTML(200, "index-server.html", nil)
}
func showMergeServiceIP(c *gin.Context) {
	ret := make([]interface{}, 0)

	services := getIcmpServices()
	for _, s := range services {
		ret = append(ret, s)
	}

	// TODO: because we haven't provided a method to remove dead/alive Grpc services yet,
	// so let us just show alive services to WebUI now.
	serviceAliveTmp := getGrpcAliveService()
	for _, s := range serviceAliveTmp {
		ret = append(ret, s)
	}

	c.JSON(200, ret)
}

func RunServer(
	report_server_addr *net.IP, report_server_port uint32, web_server_addr *net.IP, web_server_port uint32,
	influxdbUrl string, influxdbToken string, influxdbOrgBucket string,
	cli_dump_interval uint32, refresh_interval uint32, minLogLevel util.MaoLogLevel, silent bool,
	disable_gateway_module bool,
	disable_grpc_module bool,
	disable_icmp_module bool,
	disable_topology_module bool,
	disable_email_module bool,
	disable_mysql_module bool,
	disable_wechat_module bool,
	version string) {

	util.InitMaoLog(minLogLevel)

	// ====== Restful Server module - part 1/2 ======
	restfulServer := &Restful.RestfulServerImpl{}
	restfulServer.InitRestfulServer()

	MaoCommon.RegisterService(MaoApi.RestfulServerRegisterName, restfulServer)

	// register server.go's api
	//restfulServer.RegisterGetApi("/json", showServers) // Mao: Deprecated, 2022.07.08.
	//restfulServer.RegisterGetApi("/plain", showServerPlain) // Mao: Deprecated, 2022.07.08.
	restfulServer.RegisterGetApi("/showMergeServiceIP", showMergeServiceIP)
	restfulServer.RegisterUiPage("/Dashboard", showMergeServer)
	// ==============================================

	// ====== Config(YAML) module ======
	configModule := &config.ConfigYamlModule{}
	if !configModule.InitConfigModule(config.DEFAULT_CONFIG_FILE) {
		return
	}

	MaoCommon.RegisterService(MaoApi.ConfigModuleRegisterName, configModule)
	// =================================

	// ====== gRPC KA module ======
	if disable_grpc_module == false {
		grpcModule := &GrpcKa.GrpcDetectModule{}
		if !grpcModule.InitGrpcModule(parent.GetAddrPort(report_server_addr, report_server_port)) {
			return
		}

		MaoCommon.RegisterService(MaoApi.GrpcKaModuleRegisterName, grpcModule)
	}
	// ============================

	// ====== ICMP KA module ======
	if disable_icmp_module == false {
		icmpDetectModule := &icmpKa.IcmpDetectModule{}
		if !icmpDetectModule.InitIcmpModule() {
			return
		}

		MaoCommon.RegisterService(MaoApi.IcmpKaModuleRegisterName, icmpDetectModule)
	}
	// ============================

	// ====== SMTP Email module ======
	if disable_email_module == false {
		smtpEmailModule := &Email.SmtpEmailModule{}
		if !smtpEmailModule.InitSmtpEmailModule() {
			return
		}

		MaoCommon.RegisterService(MaoApi.EmailModuleRegisterName, smtpEmailModule)
	}
	// ============================

	// ====== MYSQL SYNC module ======
	if disable_mysql_module == false {
		mysqlSyncModule := &MaoDatabase.MysqlDataPublisher{}
		if !mysqlSyncModule.InitMysqlDataPublisher() {
			return
		}
	}
	// ============================

	// ====== Wechat Message module ======
	if disable_wechat_module == false {
		//wechatMessageModule := &Wechat.WechatMessageModule{}
		//if !wechatMessageModule.InitWechatMessageModule() {
		//	return
		//}
		//
		//MaoCommon.RegisterService(MaoApi.WechatModuleRegisterName, wechatMessageModule)
	}
	// ============================

	// ====== Topology module ======
	if disable_topology_module == false {
		hostname, err := util.GetHostname()
		if err != nil {
			hostname = "Mao-Unknown"
		}
		onosTopoModule := &OnosTopoShow.OnosTopoModule{}
		onosTopoModule.InitOnosTopoModule(hostname, version)

		MaoCommon.RegisterService(MaoApi.TopoModuleRegisterName, onosTopoModule)
	}
	// =================================

	// ====== MaoCloud Monitor Wrapper module ======
	maoCloudMonitorWrapper := &MaoCloudMonitor.MaoCloudMonitorWrapper{}
	maoCloudMonitorWrapper.InitMaoCloudMonitorWrapper()

	MaoCommon.RegisterService(MaoApi.MaoCloudModuleRegisterName, maoCloudMonitorWrapper)
	// =================================

	// ====== Restful Server module - part 2/2 ======
	restfulServer.StartRestfulServerDaemon(parent.GetAddrPort(web_server_addr, web_server_port))
	// ==============================================

	// ====== Aux Data Processor module ======
	InfluxDB.ConfigInfluxdbUtils(influxdbUrl, influxdbToken, influxdbOrgBucket)

	auxDataModule := &AuxDataProcessor.AuxDataProcessorModule{}
	auxDataModule.InitAuxDataProcessor()

	MaoCommon.RegisterService(MaoApi.AuxDataModuleRegisterName, auxDataModule)

	envTempProcessor := AuxDataProcessor.EnvTempProcessor{}
	var envTempProcessorAux MaoApi.AuxDataProcessor = envTempProcessor
	auxDataModule.AddProcessor(&envTempProcessorAux)
	// =======================================

	// ====== Gateway module ======
	if disable_gateway_module == false {
		gatewayModule := &Soap.TplinkGatewayModule{}
		if !gatewayModule.InitTplinkGatewayModule() {
			return
		}

		MaoCommon.RegisterService(MaoApi.GatewayModuleRegisterName, gatewayModule)
	}
	// ============================

	if !silent {
		go startCliOutput(cli_dump_interval)
	}

	traceServicesForTopologyShow()

	// updateServerAlive(refresh_interval) // Mao: Deprecated, 2022.07.08.
	for {
		time.Sleep(1 * time.Minute)
	}
}
