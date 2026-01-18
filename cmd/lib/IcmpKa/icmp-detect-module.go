package IcmpKa

import (
	MaoApi "MaoServerDiscovery/cmd/api"
	"MaoServerDiscovery/cmd/lib/Config"
	"MaoServerDiscovery/cmd/lib/MaoCommon"
	"MaoServerDiscovery/util"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	//addServiceChan *chan string
	//delServiceChan *chan string
	//serviceMirror  []*MaoIcmpService
)

const (
	MODULE_NAME = "ICMP-Detect-module"

	URL_CONFIG_HOMEPAGE        = "/configIcmp"
	URL_CONFIG_ADD_SERVICE_IP  = "/addServiceIp"
	URL_CONFIG_DEL_SERVICE_IP  = "/delServiceIp"
	URL_CONFIG_SHOW_SERVICE_IP = "/showServiceIP"



	ICMP_API_KEY_ADDRESS = "ipv4v6"
	ICMP_API_KEY_SERVICE_NAME = "serviceName"

	PROTO_ICMP    = 1
	PROTO_ICMP_V6 = 58

	ICMP_DETECT_ID    = 0x1994
	ICMP_V6_DETECT_ID = 0x1996

	SERVICE_LIST_CONFIG_PATH = "/icmp-ka/services"
)

type IcmpDetectModule struct {
	connV4       *icmp.PacketConn
	connV6       *icmp.PacketConn
	serviceStore sync.Map // address_string -> Service object

	AddChan chan *MaoApi.MaoIcmpServiceIdentifier // need to be initiated when constructing
	DelChan chan string // need to be initiated when constructing

	// TODO - MAKE IT CONFIGURABLE
	// configurable parameter
	sendInterval uint32 // milliseconds
	checkInterval uint32 // milliseconds
	leaveTimeout uint32 // milliseconds
	refreshShowingInterval uint32 //

	// TODO - MAKE IT CONFIGURABLE
	// tunable configurable parameter
	receiveFreezePeriod uint32 // milliseconds - mitigate attack with malformed packets.

	// only for web showing, i.e. external get operation
	serviceMirror []*MaoApi.MaoIcmpService
}

func (m *IcmpDetectModule) sendIcmpLoop() {
	round := 1
	for {
		util.MaoLogM(util.DEBUG, MODULE_NAME, "Detect Round %d", round)
		m.serviceStore.Range(func(_, value interface{}) bool {
			service := value.(*MaoApi.MaoIcmpService)

			addr, err := net.ResolveIPAddr("ip", service.Address)
			if err != nil {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to ResolveIPAddr v4v6Addr: %s", err.Error())
				return true // for continuous iteration
			}

			var msgType icmp.Type
			var echoId int
			var conn *icmp.PacketConn
			if util.JudgeIPv6Addr(addr) {
				msgType = ipv6.ICMPTypeEchoRequest
				echoId = ICMP_V6_DETECT_ID
				conn = m.connV6
			} else {
				msgType = ipv4.ICMPTypeEcho
				echoId = ICMP_DETECT_ID
				conn = m.connV4
			}


			// To build and send ICMP Request.

			service.DetectCount++
			icmpPayloadData := []byte(time.Now().String())
			echoMsg := icmp.Echo{
				ID:   echoId,
				Seq:  int(service.DetectCount),
				Data: icmpPayloadData,
			}

			icmpMsg := icmp.Message{
				Type: msgType,
				Code: 0,
				//Checksum: 0,
				Body: &echoMsg,
			}

			// do le->be in the Marshal
			icmpMsgByte, err := icmpMsg.Marshal(nil)
			if err != nil {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to marshal icmpMsg: %s", err.Error())
				return true
			}

			service.RttOutboundTimestamp = time.Now()
			_, err = conn.WriteTo(icmpMsgByte, addr)
			if err != nil {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to WriteTo connV6: %s", err.Error())
				return true
			}

			return true
		})
		time.Sleep(time.Duration(m.sendInterval) * time.Millisecond)
		round++
	}
}

/**
 * For IPv6: PROTO_ICMP, m.connV4
 * For IPv4: PROTO_ICMP_V6, m.connV6
 */
func (m *IcmpDetectModule) receiveProcessIcmpLoop(protoNum int, conn *icmp.PacketConn) {
	recvBuf := make([]byte, 2000)
	for {
		count, addr, err := conn.ReadFrom(recvBuf)
		lastseen := time.Now()
		if err != nil {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to recv ICMP, freeze %d ms, %s", m.receiveFreezePeriod, err.Error())
			time.Sleep(time.Duration(m.receiveFreezePeriod) * time.Millisecond)
			continue
		}

		msg, err := icmp.ParseMessage(protoNum, recvBuf)
		if err != nil {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse ICMP, freeze %d ms, %s", m.receiveFreezePeriod, err.Error())
			time.Sleep(time.Duration(m.receiveFreezePeriod) * time.Millisecond)
			continue
		}

		icmpEcho, ok := msg.Body.(*icmp.Echo)
		if !ok {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to convert *icmp.Echo, freeze %d ms", m.receiveFreezePeriod)
			time.Sleep(time.Duration(m.receiveFreezePeriod) * time.Millisecond)
			continue
		}
		util.MaoLogM(util.DEBUG, MODULE_NAME, "%v, %v = %v, %v, %v, %v, %v, %v", count, addr, msg.Type, msg.Code, msg.Checksum, icmpEcho.ID, icmpEcho.Seq, icmpEcho.Data)

		var addrStr string
		if protoNum == PROTO_ICMP_V6 {
			addrStr = strings.Split(addr.String(), "%")[0] // for ipv6 link-local address, it is suffixed by % and interface name.
		} else {
			addrStr = addr.String()
		}
		value, ok := m.serviceStore.Load(addrStr)
		if ok && value != nil {
			service := value.(*MaoApi.MaoIcmpService)
			service.LastSeen = lastseen
			service.RttDuration = service.LastSeen.Sub(service.RttOutboundTimestamp)
			service.ReportCount++

			if !service.Alive {
				service.Alive = true

				emailModule := MaoCommon.ServiceRegistryGetEmailModule()
				if emailModule == nil {
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get EmailModule, can't send UP notification")
				} else {
					emailModule.SendEmail(&MaoApi.EmailMessage{
						Subject: "ICMP UP notification",
						Content: fmt.Sprintf("Service: %s - %s\r\nUP Time: %s\r\nDetail: %v\r\n",
							service.ServiceName, service.Address, time.Now().String(), service),
					})
				}

				
				// TEMP: test wechat module
				//wechatModule := MaoCommon.ServiceRegistryGetWechatModule()
				//if wechatModule == nil {
				//	util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get WechatModule, can't send UP notification")
				//} else {
				//	wechatModule.SendWechatMessage(&MaoApi.WechatMessage{
				//		Title:       "ICMP UP notification",
				//		ContentHttp: fmt.Sprintf("Service: %s\r\nUP Time: %s\r\nDetail: %v\r\n",
				//			service.Address, time.Now().String(), service),
				//		Url:         "https://www.maojianwei.com/",
				//	})
				//}
			}
		}
	}
}

func (m *IcmpDetectModule) controlLoop() {
	checkTimer := time.NewTimer(time.Duration(m.checkInterval) * time.Millisecond)
	for {
		select {
		case addService := <-m.AddChan:
			if _, ok := m.serviceStore.Load(addService.ServiceIPv4v6); !ok {
				m.serviceStore.Store(addService.ServiceIPv4v6, &MaoApi.MaoIcmpService{
					Address:              addService.ServiceIPv4v6,
					ServiceName:          addService.ServiceName,
					Alive:                false,
					LastSeen:             time.Unix(0, 0),
					DetectCount:          0,
					ReportCount:          0,
					RttDuration:          0,
					RttOutboundTimestamp: time.Time{},
				})
				util.MaoLogM(util.DEBUG, MODULE_NAME, "Get new service %s", addService.ServiceIPv4v6)
				m.addNewServiceToConfig(addService) // TODO: TBD,支持添加servicename
			}
		case delService := <-m.DelChan:
			m.serviceStore.Delete(delService)
			util.MaoLogM(util.DEBUG, MODULE_NAME, "Del service %s", delService)
			m.removeOldServiceFromConfig(delService) // todo: TBD,支持删除servicename

			topoModule := MaoCommon.ServiceRegistryGetTopoModule()
			if topoModule == nil {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get TopoModule, can't send DELETE event")
			} else {
				topoModule.SendEvent(&MaoApi.TopoEvent{
					EventType:   MaoApi.SERVICE_DELETE,
					EventSource: MaoApi.SOURCE_ICMP,
					ServiceName: delService,
					Timestamp:   time.Now(),
				})
			}
		case <-checkTimer.C:
			// aliveness checking
			m.serviceStore.Range(func(key, value interface{}) bool {
				service := value.(*MaoApi.MaoIcmpService)
				if service.Alive && time.Since(service.LastSeen) > time.Duration(m.leaveTimeout) * time.Millisecond {
					service.Alive = false

					emailModule := MaoCommon.ServiceRegistryGetEmailModule()
					if emailModule == nil {
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get EmailModule, can't send DOWN notification")
					} else {
						emailModule.SendEmail(&MaoApi.EmailMessage{
							Subject: "ICMP DOWN notification",
							Content: fmt.Sprintf("Service: %s - %s\r\nDOWN Time: %s\r\nDetail: %v\r\n",
								service.ServiceName, service.Address, time.Now().String(), service),
						})
					}


					// TEMP: test wechat module
					//wechatModule := MaoCommon.ServiceRegistryGetWechatModule()
					//if wechatModule == nil {
					//	util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get WechatModule, can't send DOWN notification")
					//} else {
					//	wechatModule.SendWechatMessage(&MaoApi.WechatMessage{
					//		Title:       "ICMP DOWN notification",
					//		ContentHttp: fmt.Sprintf("Service: %s\r\nDOWN Time: %s\r\nDetail: %v\r\n",
					//			service.Address, time.Now().String(), service),
					//		Url:         "https://www.maojianwei.com/",
					//	})
					//}
				}
				return true
			})
			checkTimer.Reset(time.Duration(m.checkInterval) * time.Millisecond)
		}
	}
}

func (m *IcmpDetectModule) refreshShowingService() {
	for {
		time.Sleep(time.Duration(m.refreshShowingInterval) * time.Millisecond)
		servicesTmp := make([]*MaoApi.MaoIcmpService, 0)
		m.serviceStore.Range(func(_, value interface{}) bool {
			servicesTmp = append(servicesTmp, value.(*MaoApi.MaoIcmpService))
			return true
		})
		m.serviceMirror = servicesTmp
	}
}




func (m *IcmpDetectModule) getServiceConfig() (serviceList []*MaoApi.MaoIcmpServiceIdentifier) {
	// todo: TBD: 支持读取serviceName


	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return nil
	}

	serviceObj, errCode := configModule.GetConfig(SERVICE_LIST_CONFIG_PATH)
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get current services from config, errCode: %d", errCode)
		return nil
	}

	serviceList, ok := serviceObj.([]*MaoApi.MaoIcmpServiceIdentifier)
	if !ok {
		// the list is read from config file
		serviceObjList, ok := serviceObj.([]interface{})
		if !ok {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse service list config, service list is not array")
			return nil
		}
		serviceList = make([]*MaoApi.MaoIcmpServiceIdentifier, 0)
		for _, s := range serviceObjList {
			sMap, ok := s.(map[string]interface{})
			if !ok {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse service node config - map")
				return nil
			}

			addressObj, ok := sMap[MaoApi.ICMP_CONFIG_KEY_ADDRESS]
			if !ok {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse service node config - address")
				return nil
			}
			address, ok := addressObj.(string)
			if !ok {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse service node config - address is not a string")
				return nil
			}

			serviceNameObj, ok := sMap[MaoApi.ICMP_CONFIG_KEY_SERVICE_NAME]
			if !ok {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse service node config - service name")
				return nil
			}
			serviceName, ok := serviceNameObj.(string)
			if !ok {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse service node config - service name is not a string")
				return nil
			}

			service := &MaoApi.MaoIcmpServiceIdentifier{
				ServiceIPv4v6: address,
				ServiceName:   serviceName,
			}
			serviceList = append(serviceList, service)
		}
	}

	return serviceList


	//serviceList, ok := serviceObj.([]string)
	//if !ok {
	//	// the list is read from config file
	//	serviceIntfList, ok := serviceObj.([]interface{})
	//	if !ok {
	//		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse serviceList config, []string and []interface{}")
	//		return nil
	//	}
	//	serviceList = make([]string, 0)
	//	for _, s := range serviceIntfList {
	//		serviceList = append(serviceList, s.(string))
	//	}
	//}
	//return serviceList
}

func (m *IcmpDetectModule) saveServiceConfig(serviceList []*MaoApi.MaoIcmpServiceIdentifier) (success bool){
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return false
	}

	_, errCode := configModule.PutConfig(SERVICE_LIST_CONFIG_PATH, serviceList) // TODO: 是否可以存对象？
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to put current services to config, errCode: %d", errCode)
		return false
	}

	return true
}

func (m *IcmpDetectModule) addNewServiceToConfig(service *MaoApi.MaoIcmpServiceIdentifier) (success bool) {
	currentServices := m.getServiceConfig()
	if currentServices == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get current services from config")
		return false
	}

	for _, serviceExist := range currentServices {
		if serviceExist.ServiceIPv4v6 == service.ServiceIPv4v6 {
			// Mainly for reading config during initialization phase.
			return true
		}
	}
	currentServices = append(currentServices, service)

	return m.saveServiceConfig(currentServices)
}

func (m *IcmpDetectModule) removeOldServiceFromConfig(serviceAddr string) (success bool) {
	currentServices := m.getServiceConfig()
	if currentServices == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get current services from config")
		return false
	}

	// assume that: the service address appears only once in the config
	for index, s := range currentServices {
		if s.ServiceIPv4v6 == serviceAddr {
			currentServices = append(currentServices[:index], currentServices[index+1:]...)
			m.saveServiceConfig(currentServices)
			return true
		}
	}

	util.MaoLogM(util.WARN, MODULE_NAME, "Can't find the service in the config, can't remove it, service: %s", serviceAddr)
	return false
}

func (m *IcmpDetectModule) initConfigPath() (success bool, serviceConfig []*MaoApi.MaoIcmpServiceIdentifier) {
	services := m.getServiceConfig()
	if services != nil {
		return true, services
	}

	// the config doesn't exist, init it.

	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return false, nil
	}

	_, errCode := configModule.PutConfig(SERVICE_LIST_CONFIG_PATH, make([]*MaoApi.MaoIcmpServiceIdentifier, 0)) // TODO-DEBUG
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to put empty string array to config, errCode: %d", errCode)
		return false, nil
	}

	return true, services
}




func (m *IcmpDetectModule) AddService(service *MaoApi.MaoIcmpServiceIdentifier) {
	if net.ParseIP(service.ServiceIPv4v6) != nil {
		m.AddChan <- service
	}
}

func (m *IcmpDetectModule) DelService(serviceIPv4v6 string) {
	if net.ParseIP(serviceIPv4v6) != nil {
		m.DelChan <- serviceIPv4v6
	}
}



func (m *IcmpDetectModule) InitIcmpModule() bool {
	var err error
	m.connV4, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		util.MaoLogM(util.ERROR, MODULE_NAME, "Fail to listen ICMP, %s", err.Error())
		return false
	}
	util.MaoLogM(util.INFO, MODULE_NAME, "Listen ICMP ok")

	m.connV6, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		util.MaoLogM(util.ERROR, MODULE_NAME, "Fail to listen ICMPv6, %s", err.Error())
		return false
	}
	util.MaoLogM(util.INFO, MODULE_NAME, "Listen ICMPv6 ok")



	m.AddChan = make(chan *MaoApi.MaoIcmpServiceIdentifier, 50)
	m.DelChan = make(chan string, 50)

	if success, services := m.initConfigPath(); !success {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to init config.")
	} else {
		for _, s := range services {
			m.AddService(s)
		}
		util.MaoLogM(util.INFO, MODULE_NAME, "Services loaded from config: %s", services)
	}

	// configurable parameter
	m.sendInterval = 500
	m.checkInterval = 500
	m.leaveTimeout = 2000
	m.refreshShowingInterval = 1000

	// tunable configurable parameter
	m.receiveFreezePeriod = 10
	m.serviceMirror = make([]*MaoApi.MaoIcmpService, 0)


	go m.receiveProcessIcmpLoop(PROTO_ICMP, m.connV4)
	go m.receiveProcessIcmpLoop(PROTO_ICMP_V6, m.connV6)
	go m.sendIcmpLoop()
	go m.controlLoop()

	go m.refreshShowingService()

	m.configRestControlInterface()

	return true
}



func (m *IcmpDetectModule) GetServices() []*MaoApi.MaoIcmpService {
	tmp := m.serviceMirror
	sort.Slice(tmp, func(i, j int) bool {
		return tmp[i].Address < tmp[j].Address
	})
	return tmp
}

func showConfigPage(c *gin.Context) {
	c.HTML(200, "index-icmp.html", nil)
}

func (m *IcmpDetectModule) showServiceIps(c *gin.Context) {
	c.JSON(200, m.GetServices())
}


func (m *IcmpDetectModule) parseService(c *gin.Context) []*MaoApi.MaoIcmpServiceIdentifier {
	services := make([]*MaoApi.MaoIcmpServiceIdentifier, 0)

	var formData map[string]interface{}
	err := c.ShouldBindJSON(&formData)
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse form data, not a map.")
		return services
	}

	serviceIpNameListObj, ok := formData["serviceIpName"]
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse serviceIpNameListObj, not found.")
		return services
	}

	serviceIpNameList, ok := serviceIpNameListObj.([]interface{})
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse serviceIpNameList, not an array.")
		return services
	}

	for _, serviceIpNameObj := range serviceIpNameList {
		serviceIpName, ok := serviceIpNameObj.(map[string]interface{})
		if !ok {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse serviceIpName, not an map.")
			return services
		}

		addressObj, ok := serviceIpName[MaoApi.ICMP_CONFIG_KEY_ADDRESS]
		if !ok {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse addressObj, not found.")
			return make([]*MaoApi.MaoIcmpServiceIdentifier, 0) // empty array
		}
		address, ok := addressObj.(string)
		if !ok {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse address, not a string.")
			return make([]*MaoApi.MaoIcmpServiceIdentifier, 0) // empty array
		}

		serviceName := ""
		serviceNameObj, ok := serviceIpName[MaoApi.ICMP_CONFIG_KEY_SERVICE_NAME]
		if ok {
			serviceName, ok = serviceNameObj.(string)
			if !ok {
				util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse serviceName, not a string.")
				serviceName = "Unknown"
			}
			if serviceName == "" {
				serviceName = "Unknown"
			}
		} else {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse serviceNameObj, not found.")
			serviceName = "Unknown"
		}

		service := &MaoApi.MaoIcmpServiceIdentifier{
			ServiceIPv4v6: address,
			ServiceName:   serviceName,
		}

		services = append(services, service)
	}

	return services
}

func (m *IcmpDetectModule) processServiceIp(c *gin.Context) {

	if strings.Contains(c.FullPath(), URL_CONFIG_ADD_SERVICE_IP) {
		serviceIpNameList := m.parseService(c)
		for _, serviceIpName := range serviceIpNameList {
			m.AddService(serviceIpName)
		}
	} else {
		v4Ip, ok := c.GetPostForm("ipv4v6")
		if ok {
			v4IpArr := strings.Fields(v4Ip)
			for _, s := range v4IpArr {
				m.DelService(s)
			}
		}
	}

	showConfigPage(c)
}


func (m *IcmpDetectModule) configRestControlInterface() {
	restfulServer := MaoCommon.ServiceRegistryGetRestfulServerModule()
	if restfulServer == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get RestfulServerModule, unable to register restful apis.")
		return
	}

	restfulServer.RegisterUiPage(URL_CONFIG_HOMEPAGE, showConfigPage)
	restfulServer.RegisterGetApi(URL_CONFIG_SHOW_SERVICE_IP, m.showServiceIps)

	restfulServer.RegisterPostApi(URL_CONFIG_ADD_SERVICE_IP, m.processServiceIp)
	restfulServer.RegisterPostApi(URL_CONFIG_DEL_SERVICE_IP, m.processServiceIp)
}
