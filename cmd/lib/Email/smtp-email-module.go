package Email

import (
	MaoApi "MaoServerDiscovery/cmd/api"
	"MaoServerDiscovery/cmd/lib/Config"
	"MaoServerDiscovery/cmd/lib/MaoCommon"
	"MaoServerDiscovery/cmd/lib/MaoEnhancedGolang"
	"MaoServerDiscovery/util"
	"crypto/tls"
	"fmt"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
)

const (
	MODULE_NAME = "SMTP-Email-module"

	SUBJECT_FIX_PREFIX = "MaoReport: "

	URL_EMAIL_HOMEPAGE = "/configEmail"
	URL_EMAIL_CONFIG   = "/addEmailInfo"
	URL_EMAIL_SHOW   = "/getEmailInfo"

	EMAIL_INFO_CONFIG_PATH_ROOT     = "/email"
	EMAIL_INFO_CONFIG_PATH_PASSWORD = "/email/password"

	EMAIL_CONFIG_KEY_USERNAME = "username"
	EMAIL_CONFIG_KEY_SERVER_ADDRPORT = "smtpServerAddrPort"
	EMAIL_CONFIG_KEY_SENDER = "sender"
	EMAIL_CONFIG_KEY_RECEIVER = "receiver"

	EMAIL_API_KEY_USERNAME = EMAIL_CONFIG_KEY_USERNAME
	EMAIL_API_KEY_PASSWORD = "password"
	EMAIL_API_KEY_SERVER_ADDRPORT = EMAIL_CONFIG_KEY_SERVER_ADDRPORT
	EMAIL_API_KEY_SENDER = EMAIL_CONFIG_KEY_SENDER
	EMAIL_API_KEY_RECEIVER = EMAIL_CONFIG_KEY_RECEIVER
)

type SmtpEmailModule struct {

	username           string
	password           string // Attention: password can't be outputted !!!
	smtpServerAddrPort string // addr:port, default port for smtp is 25.
	sender string
	receiver []string


	// input the message
	sendEmailChannel chan *MaoApi.EmailMessage
	lastSendTimestamp time.Time

	secConfigChannel chan int

	// same as the other module, it is expected to be global
	//checkInterval uint32

	needShutdown bool
}

func (s *SmtpEmailModule) RequireShutdown() {
	s.needShutdown = true
}


func (s *SmtpEmailModule) SendEmail(message *MaoApi.EmailMessage) {
	s.sendEmailChannel <- message
}

func (s *SmtpEmailModule) checkEmailInfo() bool {

	// password may be empty?
	if s.username == "" || s.smtpServerAddrPort == "" || s.sender == "" || len(s.receiver) == 0 {
		// can adapt to "s.receiver == nil"
		return false
	}
	return true
}


func (s *SmtpEmailModule) sendEmail(m *MaoApi.EmailMessage) {

	if !s.checkEmailInfo() {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to send email, please config email info first.")
		return
	}

	// Set up authentication information everytime, that allows to update:
	// username, password, smtpServerAddrPort, sender, receiver
	auth := AuthLOGIN(s.username, s.password)

	// TODO: how to build multiple receivers string?
	// TODO: support multiple receivers
	msg := fmt.Sprintf("To: %s\r\n" +
		"Subject: %s%s\r\n" + "\r\n" +
		"%s\r\n",
		s.receiver[0], SUBJECT_FIX_PREFIX, m.Subject, m.Content)

	//msg := []byte("To: @.com\r\n" +
	//	"Subject: MaoReport: beijing tower\r\n" +
	//	"\r\n" +
	//	"This is the email body.\r\n")

	// TODO: make it configurable
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	err := MaoEnhancedGolang.SendMail(s.smtpServerAddrPort, auth, s.sender, s.receiver, []byte(msg), tlsConfig)
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to send email, %s", err.Error())
	}
}

func (s *SmtpEmailModule) sendEmailLoop() {
	checkInterval := time.Duration(1000) * time.Millisecond
	checkShutdownTimer := time.NewTimer(checkInterval)
	for {
		select {
		case message := <-s.sendEmailChannel:
			if time.Now().Sub(s.lastSendTimestamp) < 10 * time.Second {
				freezeTimer := time.NewTimer(time.Duration(10) * time.Second)
				sent := false
				for !sent {
					select {
					case <-freezeTimer.C:
						util.MaoLogM(util.INFO, MODULE_NAME, "Sending email, pending: %d", len(s.sendEmailChannel))
						s.sendEmail(message)
						s.lastSendTimestamp = time.Now()
						sent = true
					case <-checkShutdownTimer.C:
						util.MaoLogM(util.DEBUG, MODULE_NAME, "CheckShutdown while freezing, event queue len %d", len(s.sendEmailChannel))
						if s.needShutdown {
							util.MaoLogM(util.WARN, MODULE_NAME, "Exit while freezing, the sendEmailChannel len: %d", len(s.sendEmailChannel))
							return
						}
						checkShutdownTimer.Reset(checkInterval)
					}
				}
			} else {
				util.MaoLogM(util.INFO, MODULE_NAME, "Sending email, pending: %d", len(s.sendEmailChannel))
				s.sendEmail(message)
				s.lastSendTimestamp = time.Now()
			}

		case <-s.secConfigChannel:
			s.loadEmailSecConfig()
		case <-checkShutdownTimer.C:
			util.MaoLogM(util.DEBUG, MODULE_NAME, "CheckShutdown, event queue len %d", len(s.sendEmailChannel))
			if s.needShutdown {
				if len(s.sendEmailChannel) != 0 {
					util.MaoLogM(util.WARN, MODULE_NAME, "Exiting, but the sendEmailChannel is not empty, len: %d", len(s.sendEmailChannel))
				}
				util.MaoLogM(util.INFO, MODULE_NAME, "Exit.")
				return
			}
			checkShutdownTimer.Reset(checkInterval)
		}
	}
}

func (s *SmtpEmailModule) InitSmtpEmailModule() bool {
	s.sendEmailChannel = make(chan *MaoApi.EmailMessage, 1024)
	s.secConfigChannel = make(chan int)
	s.needShutdown = false


	s.registerSecConfigListener()
	s.loadEmailConfig()

	go s.sendEmailLoop()

	s.configRestControlInterface()

	return true
}

func (s *SmtpEmailModule) registerSecConfigListener() {
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return
	}

	// register config-secKey listener
	configModule.RegisterKeyUpdateListener(&s.secConfigChannel)
}
func (s *SmtpEmailModule) loadEmailSecConfig() {
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return
	}

	password, errCode := configModule.GetSecConfig(EMAIL_INFO_CONFIG_PATH_PASSWORD)
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to read email config, code: %d, %v", errCode, errCode)
		return
	}

	var ok bool
	s.password, ok = password.(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config - password")
		return
	}

	util.MaoLogM(util.INFO, MODULE_NAME, "Loaded sec config")
}
func (s *SmtpEmailModule) loadEmailConfig() {
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return
	}

	emailConfig, errCode := configModule.GetConfig(EMAIL_INFO_CONFIG_PATH_ROOT)
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to read email config, code: %d, %v", errCode, errCode)
		return
	}
	if emailConfig == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "There is no email config. You may need to config email module.")
		return
	}

	emailConfigMap, ok := emailConfig.(map[string]interface{})
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config, can't convert to map[string]interface{}")
		return
	}

	username, ok := emailConfigMap[EMAIL_CONFIG_KEY_USERNAME].(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config - username")
		return
	}
	smtpServerAddrPort, ok := emailConfigMap[EMAIL_CONFIG_KEY_SERVER_ADDRPORT].(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config - smtpServerAddrPort")
		return
	}
	sender, ok := emailConfigMap[EMAIL_CONFIG_KEY_SENDER].(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config - sender")
		return
	}
	receiverIntfs, ok := emailConfigMap[EMAIL_CONFIG_KEY_RECEIVER].([]interface{})
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config - receiver")
		return
	}
	receivers := make([]string, 0)
	for _, receiverIntf := range receiverIntfs {
		if r, ok := receiverIntf.(string); ok {
			receivers = append(receivers, r)
		} else {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse email config - receiverIntf")
			return
		}
	}

	s.username = username
	s.smtpServerAddrPort = smtpServerAddrPort
	s.sender = sender
	s.receiver = receivers
}


func (s *SmtpEmailModule) configRestControlInterface() {
	restfulServer := MaoCommon.ServiceRegistryGetRestfulServerModule()
	if restfulServer == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get RestfulServerModule, unable to register restful apis.")
		return
	}

	restfulServer.RegisterUiPage(URL_EMAIL_HOMEPAGE, s.showEmailPage)
	restfulServer.RegisterGetApi(URL_EMAIL_SHOW, s.showEmailInfo)
	restfulServer.RegisterPostApi(URL_EMAIL_CONFIG, s.processEmailInfo)
}

func (s *SmtpEmailModule) showEmailPage(c *gin.Context) {
	c.HTML(200, "index-email.html", nil)
}

func (s *SmtpEmailModule) showEmailInfo(c *gin.Context) {
	data := make(map[string]interface{})
	data[EMAIL_CONFIG_KEY_USERNAME] = s.username
	data[EMAIL_CONFIG_KEY_SERVER_ADDRPORT] = s.smtpServerAddrPort
	data[EMAIL_CONFIG_KEY_SENDER] = s.sender
	data[EMAIL_CONFIG_KEY_RECEIVER] = s.receiver

	// Attention: password can't be outputted !!!
	c.JSON(200, data)
}

func (s *SmtpEmailModule) processEmailInfo(c *gin.Context) {

	// TODO: check email address, limit the length of username/password/email. Prevent injection attack

	username, ok := c.GetPostForm(EMAIL_API_KEY_USERNAME)
	if ok {
		s.username = username
	}

	password, ok := c.GetPostForm(EMAIL_API_KEY_PASSWORD)
	if ok {
		s.password = password
	}

	smtpServerAddrPort, ok := c.GetPostForm(EMAIL_API_KEY_SERVER_ADDRPORT)
	if ok {
		s.smtpServerAddrPort = smtpServerAddrPort
	}

	sender, ok := c.GetPostForm(EMAIL_API_KEY_SENDER)
	if ok {
		s.sender = sender
	}

	receiverStr, ok := c.GetPostForm(EMAIL_API_KEY_RECEIVER)
	if ok {
		receivers := strings.Fields(receiverStr)
		s.receiver = receivers
	}

	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance, can't save email info")
	} else {
		data := make(map[string]interface{})
		data[EMAIL_CONFIG_KEY_USERNAME] = s.username
		data[EMAIL_CONFIG_KEY_SERVER_ADDRPORT] = s.smtpServerAddrPort
		data[EMAIL_CONFIG_KEY_SENDER] = s.sender
		data[EMAIL_CONFIG_KEY_RECEIVER] = s.receiver

		// Attention: password can't be outputted !!!
		configModule.PutConfig(EMAIL_INFO_CONFIG_PATH_ROOT, data)
		configModule.PutSecConfig(EMAIL_INFO_CONFIG_PATH_PASSWORD, s.password)
	}

	s.showEmailPage(c)
}