package Config

import (
	"MaoServerDiscovery/cmd/lib/MaoCommon"
	"MaoServerDiscovery/util"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/MaoJianwei/gmsm/sm3"
	"github.com/MaoJianwei/gmsm/sm4"
	"github.com/gin-gonic/gin"
	yaml "gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const (
	DEFAULT_CONFIG_FILE = "mao-config.yaml"

	EVENT_GET = iota
	EVENT_PUT
	EVENT_GET_SEC
	EVENT_PUT_SEC

	MODULE_NAME = "Config-YAML-module"

	ERR_CODE_SUCCESS           = 0
	ERR_CODE_PATH_FORMAT       = 1
	ERR_CODE_PATH_NOT_EXIST    = 2
	ERR_CODE_PATH_TRANSIT_FAIL = 3
	ERR_CODE_SEC_PATH_NOT_EXIST = 4
	ERR_CODE_SEC_DATA_TYPE_NOT_STRING = 5

	ERR_CODE_ENC_DEC_OK                = 20
	ERR_CODE_ENC_FAIL                  = 21
	ERR_CODE_DEC_FAIL                  = 22
	ERR_CODE_DEC_NOT_ENC               = 23
	ERR_CODE_DEC_IV_PARSE_FAIL         = 24
	ERR_CODE_ENC_IV_GEN_FAIL           = 25
	ERR_CODE_ENC_DEC_KEY_NOT_READY     = 26
	ERR_CODE_ENC_INPUT_NOT_STRING_FAIL = 27

	ENC_DEC_SUFFIX_CIPHER = "_MAO_SEC"
	ENC_DEC_SUFFIX_IV     = "_MAO_SEC_IV"

	URL_CONFIG_ALL_TEXT_SHOW = "/getAllConfigText"
	URL_CONFIG_SET_SECKEY = "/setConfigSecKey"

	CONFIG_API_KEY_SECKEY = "secKey"

	CONFIG_PATH_SEC_KEY_DIGEST = "/config/secKeyDigest"
)

type ConfigYamlModule struct {
	needShutdown bool
	eventChannel chan *configEvent

	configFilename string

	secKey string // complement or truncate the key to 32-bytes length for encryption and decryption. But store the hash of the origin key.
	secKeyDigest string
	keyUpdateListeners []*chan int
}

//var (
//	needShutdown = false
//	eventChannel = make(chan *configEvent, 100)
//)

type configEvent struct {
	eventType int
	path      string

	data      interface{} // plaintext, or ciphertext updated internally
	iv        interface{} // rewrite internally before using

	result    chan eventResult
}

type eventResult struct {
	errCode int
	result  interface{}
}

func (C *ConfigYamlModule) saveConfig(config map[string]interface{}) error {
	data, _ := yaml.Marshal(config)
	return ioutil.WriteFile(C.configFilename, data, 0666)
}

func (C *ConfigYamlModule) loadConfig() (map[string]interface{}, error) {

	config := make(map[string]interface{})

	content, err := ioutil.ReadFile(C.configFilename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (C *ConfigYamlModule) GetConfig(path string) (object interface{}, errCode int) {
	result := make(chan eventResult, 1)
	event := &configEvent{
		eventType: EVENT_GET,
		path:      path,
		data:      nil,
		result:    result,
	}
	C.eventChannel <- event

	// TODO: timeout mechanism
	ret := <-result

	util.MaoLogM(util.DEBUG, MODULE_NAME, "GetConfig result: %v", ret)
	return ret.result, ret.errCode
}

// PutConfig
// path: e.g. /version, /icmp-detect/services
// result: bool, true or false
func (C *ConfigYamlModule) PutConfig(path string, data interface{}) (success bool, errCode int) {

	result := make(chan eventResult, 1)
	event := &configEvent{
		eventType: EVENT_PUT,
		path:      path,
		data:      data,
		result:    result,
	}
	C.eventChannel <- event

	// TODO: timeout mechanism
	ret := <-result
	retBool := false
	if ret.result != nil {
		retBool = ret.result.(bool)
	}

	util.MaoLogM(util.DEBUG, MODULE_NAME, "PutConfig result: %v, %v", ret, retBool)
	return retBool, ret.errCode
}

func (C *ConfigYamlModule) GetSecConfig(path string) (object interface{}, errCode int) {
	// TODO - TBD - test
	result := make(chan eventResult, 1)
	event := &configEvent{
		eventType: EVENT_GET_SEC,
		path:      path,
		data:      nil,
		result:    result,
	}
	C.eventChannel <- event

	// TODO: timeout mechanism
	ret := <-result

	util.MaoLogM(util.DEBUG, MODULE_NAME, "GetSecConfig result: %v", ret)
	return ret.result, ret.errCode
}
func (C *ConfigYamlModule) PutSecConfig(path string, data interface{}) (success bool, errCode int) {
	// todo - TBD - test
	result := make(chan eventResult, 1)
	event := &configEvent{
		eventType: EVENT_PUT_SEC,
		path:      path,
		data:      data,
		result:    result,
	}
	C.eventChannel <- event

	// TODO: timeout mechanism
	ret := <-result
	retBool := false
	if ret.result != nil {
		retBool = ret.result.(bool)
	}

	util.MaoLogM(util.DEBUG, MODULE_NAME, "PutSecConfig result: %v, %v", ret, retBool)
	return retBool, ret.errCode
}


func (C *ConfigYamlModule) eventLoop(config map[string]interface{}) {
	checkInterval := time.Duration(1000) * time.Millisecond
	checkShutdownTimer := time.NewTimer(checkInterval)
	for {
		select {
		case event := <-C.eventChannel:

			//var posMap map[string]interface{}


			paths := strings.Split(event.path, "/")
			if paths[0] != "" || paths[len(paths)-1] == "" {
				event.result <- eventResult{
					errCode: ERR_CODE_PATH_FORMAT,
					result:  nil,
				}
				util.MaoLogM(util.WARN, MODULE_NAME, "format of config path is not correct.")
				continue
			}

			transitPaths := paths[1 : len(paths)-1] // [a, b)
			transitConfig := config
			var ok = true

			var missPos int
			var tmpPath string
			var needTerminate = false
			for missPos, tmpPath = range transitPaths {
				tmpObj := transitConfig[tmpPath]
				if tmpObj == nil {
					// We meet a nonexistent path, or the data is nil.

					// Get operation: fail. (nonexistent path / data is nil)
					// Put operation: need to create all transit path to store the data. (nonexistent path / data is nil)
					// Put operation: if nil is in the config or the new data is nil, we will remove it or override it automatically,
					//                because it is not allowed that the config contain nil.
					ok = false
					break
				}

				// if obj is not map, get (nil, false) --- if it is Put operation, you need to Put nil to delete the stale data first, then retry to Put data again.
				// if obj is nil, get (nil, false) --- avoid by the above --- And, it is not allowed that the config contain nil.
				// if obj is not exist, get (nil, false) --- avoid by the above
				transitConfig, ok = tmpObj.(map[string]interface{})
				if !ok {
					// Put Operation: there is valid data, we can not override it automatically.
					// Get Operation: we cannot transit forward anymore
					event.result <- eventResult{
						errCode: ERR_CODE_PATH_TRANSIT_FAIL,
						result:  nil,
					}
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to transit the specific config path.")
					needTerminate = true
					break // needTerminate -> continue
				}
				util.MaoLogM(util.DEBUG, MODULE_NAME, "%v", transitConfig)
			}
			if needTerminate {
				continue
			}
			util.MaoLogM(util.DEBUG, MODULE_NAME, "We get the transitConfig: %v, %v", transitConfig, missPos)



			switch event.eventType {
			case EVENT_GET_SEC:
				// TODO: refactor

				util.MaoLogM(util.DEBUG, MODULE_NAME, "EVENT_GET, %s, %v, %v",
					event.path, event.data, event.result)

				if !ok {
					//log.Println("out of the for, ", eventResult{
					//	errCode: ERR_CODE_PATH_TRANSIT_FAIL,
					//	result:  nil,
					//}) // event.result <-
					event.result <- eventResult{
						errCode: ERR_CODE_PATH_TRANSIT_FAIL,
						result:  nil,
					}
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to transit the specific config path.")
				} else {
					cipherPath := fmt.Sprintf("%s%s", paths[len(paths)-1], ENC_DEC_SUFFIX_CIPHER)
					ivPath := fmt.Sprintf("%s%s", paths[len(paths)-1], ENC_DEC_SUFFIX_IV)
					errCode := ERR_CODE_SUCCESS

					ciphertext, okCiphertext := transitConfig[cipherPath]
					ivBase64, okIV := transitConfig[ivPath]
					if !okCiphertext || !okIV {
						errCode = ERR_CODE_SEC_PATH_NOT_EXIST
						event.result <- eventResult{
							errCode: errCode,
							result:  nil,
						}
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to decrypt the config: %d", errCode)
						continue
					}

					ciphertextStr, okCiphertextStr := ciphertext.(string)
					ivBase64Str, okIvBase64Str := ivBase64.(string)
					if !okCiphertextStr || !okIvBase64Str {
						errCode = ERR_CODE_SEC_DATA_TYPE_NOT_STRING
						event.result <- eventResult{
							errCode: errCode,
							result:  nil,
						}
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to decrypt the config: %d", errCode)
						continue
					}

					plaintext, errCode, err := C.decryptConfig(ciphertextStr, ivBase64Str)
					if err != nil {
						event.result <- eventResult{
							errCode: errCode,
							result:  nil,
						}
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to decrypt the config: %d, %s", errCode, err.Error())
						continue
					}

					event.result <- eventResult{
						errCode: ERR_CODE_SUCCESS,
						result: plaintext,
					}
					util.MaoLogM(util.DEBUG, MODULE_NAME, "Get operation: [SEC-INFO]")
				}

			case EVENT_GET:
				util.MaoLogM(util.DEBUG, MODULE_NAME, "EVENT_GET, %s, %v, %v",
					event.path, event.data, event.result)

				if !ok {
					//log.Println("out of the for, ", eventResult{
					//	errCode: ERR_CODE_PATH_TRANSIT_FAIL,
					//	result:  nil,
					//}) // event.result <-
					event.result <- eventResult{
						errCode: ERR_CODE_PATH_TRANSIT_FAIL,
						result:  nil,
					}
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to transit the specific config path.")
				} else {
					result, ok := transitConfig[paths[len(paths)-1]]
					if ok {
						event.result <- eventResult{
							errCode: ERR_CODE_SUCCESS,
							result: result,
						}
						util.MaoLogM(util.DEBUG, MODULE_NAME, "Get operation: %v, %v", result, ok)
					} else {
						event.result <- eventResult{
							errCode: ERR_CODE_PATH_NOT_EXIST,
							result: nil,
						}
						util.MaoLogM(util.DEBUG, MODULE_NAME, "Get operation: %v, %v", result, ok)
					}
				}

				// Old logic
				//result, err := posMap[paths[len(paths)-1]]
				//if err {
				//	event.result <- eventResult{
				//		errCode: ERR_CODE_SUCCESS,
				//		result:  result,
				//	}
				//} else {
				//	event.result <- eventResult{
				//		errCode: ERR_CODE_PATH_NOT_EXIST,
				//		result:  nil, // result is also nil.
				//	}
				//}

			case EVENT_PUT_SEC:
				// TODO: refactor

				if event.data != nil {
					plaintext, okDataType := event.data.(string)
					if !okDataType {
						// The type of data to be encrypted must be string.
						errCode := ERR_CODE_ENC_INPUT_NOT_STRING_FAIL
						event.result <- eventResult{
							errCode: errCode,
							result:  false,
						}
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to encrypt the config: %d", errCode)
						continue
					}

					cipherText, ivBase64, errCode, err := C.encryptConfig(plaintext)
					if err != nil {
						event.result <- eventResult{
							errCode: errCode,
							result:  false,
						}
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to encrypt the config: %d", errCode)
						continue
					}

					event.data = cipherText
					event.iv = ivBase64
				}
				fallthrough
			case EVENT_PUT:
				util.MaoLogM(util.DEBUG, MODULE_NAME, "EVENT_PUT, %s, %v, %v", event.path, event.data, event.result)

				if !ok {
					// Create transit path, and move transitConfig forward.
					// If nil is in the config, we will remove it or override it automatically here.
					util.MaoLogM(util.DEBUG, MODULE_NAME, "%v, %v, %v, %v, %v", transitConfig, transitPaths, len(transitPaths), missPos, transitPaths[missPos])
					for ; missPos < len(transitPaths); missPos++ {
						var newMap = make(map[string]interface{})
						transitConfig[transitPaths[missPos]] = newMap
						transitConfig = newMap
					}
					util.MaoLogM(util.DEBUG, MODULE_NAME, "Transit created, we get the transitConfig: %v", transitConfig)
				}

				// put nil means to delete. It is not allowed that the config contain nil.
				if event.data == nil {
					// todo: iterate from bottom to top, to delete empty map
					delete(transitConfig, paths[len(paths)-1])
				} else {
					if event.eventType == EVENT_PUT_SEC {
						cipherPath := fmt.Sprintf("%s%s", paths[len(paths)-1], ENC_DEC_SUFFIX_CIPHER)
						ivPath := fmt.Sprintf("%s%s", paths[len(paths)-1], ENC_DEC_SUFFIX_IV)
						transitConfig[cipherPath] = event.data
						transitConfig[ivPath] = event.iv
					} else {
						transitConfig[paths[len(paths)-1]] = event.data
					}
				}
				event.result <- eventResult{
					errCode: ERR_CODE_SUCCESS,
					result:  true,
				}
				util.MaoLogM(util.DEBUG, MODULE_NAME, "After config: %v", config)

				err := C.saveConfig(config)
				if err != nil {
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to save config, we will lose config after reboot. (%s)", err.Error())
				}

				// Old Logic
				//posMap[paths[len(paths)-1]] = event.data
				//event.result <- eventResult{
				//	errCode: ERR_CODE_SUCCESS,
				//	result:  true,
				//}
			}
		case <-checkShutdownTimer.C:
			util.MaoLogM(util.DEBUG, MODULE_NAME, "CheckShutdown, event queue len %d", len(C.eventChannel))
			if C.needShutdown && len(C.eventChannel) == 0 {
				util.MaoLogM(util.INFO, MODULE_NAME, "Exit.")
				return
			}
			checkShutdownTimer.Reset(checkInterval)
		}
	}
}



func (C *ConfigYamlModule) isKeyReady() bool {
	return C.secKey != ""
}
func (C *ConfigYamlModule) generateKeyDigest(key string) string {
	digest := sm3.Sm3Sum([]byte(key))
	keyBase64 := base64.StdEncoding.EncodeToString(digest) // convert iv to iv_base64.
	return keyBase64
}


func (C *ConfigYamlModule) generateIV() ([]byte, error) {
	// TODO: debug

	iv := make([]byte, 12)
	// 从加密安全的随机源读取数据。使用crypto/rand包，它生成的随机数具有加密安全性
	_, err := rand.Read(iv)

	return iv, err
}

func (C *ConfigYamlModule) getFixedSecKey() []byte {
	keyBytes := []byte(C.secKey)

	result := make([]byte, 16)
	for i := 0; i < 16; i += 2 {
		result[i] = '\x08'
		result[i+1] = '\x98'
	}

	copyLen := len(keyBytes)
	if copyLen > 16 {
		copyLen = 16
	}

	copy(result[:copyLen], keyBytes[:copyLen])

	return result
}

// Return cipherTextBase64, iv_base64, err_code, error
func (C *ConfigYamlModule) encryptConfig(plainText string) (string, string, int, error) {
	// TODO: debug

	if !C.isKeyReady() {
		return "", "", ERR_CODE_ENC_DEC_KEY_NOT_READY, errors.New("key not ready")
	}

	iv, err := C.generateIV()
	if err != nil {
		return "", "", ERR_CODE_ENC_IV_GEN_FAIL, err
	}

	gcmMsg, _, err := sm4.Sm4GCM(C.getFixedSecKey(), iv, []byte(plainText), nil, true) // todo - --- TO check nil A
	if err != nil {
		return "", "", ERR_CODE_ENC_FAIL, err
	}

	ivBase64 := base64.StdEncoding.EncodeToString(iv) // convert iv to iv_base64.
	gcmMsgBase64 := base64.StdEncoding.EncodeToString(gcmMsg) // convert iv to iv_base64.


	return gcmMsgBase64, ivBase64, ERR_CODE_ENC_DEC_OK, nil
}

// Return plaintext, err_code, error
func (C *ConfigYamlModule) decryptConfig(cipherTextBase64 string, ivBase64 string) (string, int, error) {
	// TODO: debug

	if !C.isKeyReady() {
		return "", ERR_CODE_ENC_DEC_KEY_NOT_READY, errors.New("key not ready")
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64) // convert iv_base64 to iv.
	if err != nil {
		return "", ERR_CODE_DEC_IV_PARSE_FAIL, err
	}

	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64) // convert iv_base64 to iv.
	if err != nil {
		return "", ERR_CODE_DEC_IV_PARSE_FAIL, err
	}

	gcmDec, _, err := sm4.Sm4GCM(C.getFixedSecKey(), iv, cipherText, nil, false) // todo - --- TO check nil A
	if err != nil {
		return "", ERR_CODE_DEC_FAIL, err
	}

	return string(gcmDec), ERR_CODE_ENC_DEC_OK, nil
}


func (C *ConfigYamlModule) RegisterKeyUpdateListener(listener *chan int) {
	// TODO: to check parallel access problem
	C.keyUpdateListeners = append(C.keyUpdateListeners, listener)
}
func (C *ConfigYamlModule) publishKeyUpdate() {
	for _, listener := range C.keyUpdateListeners {
		*listener <- 0
	}
}




func (C *ConfigYamlModule) RequireShutdown() {
	C.needShutdown = true
}

func fileIsNotExist(fileName string) bool {
	_, err := os.Stat(fileName)
	return err != nil && os.IsNotExist(err)
}

func (C *ConfigYamlModule) configRestControlInterface() {
	restfulServer := MaoCommon.ServiceRegistryGetRestfulServerModule()
	if restfulServer == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get RestfulServerModule, unable to register restful apis.")
		return
	}

	restfulServer.RegisterGetApi(URL_CONFIG_ALL_TEXT_SHOW, C.showAllConfigText)
	restfulServer.RegisterPostApi(URL_CONFIG_SET_SECKEY, C.setSecKey)
}

func (C *ConfigYamlModule) showAllConfigText(c *gin.Context) {
	content, err := ioutil.ReadFile(C.configFilename)
	if err != nil {
		c.String(200, err.Error())
	} else {
		c.String(200, string(content))
	}
}


func (C *ConfigYamlModule) setSecKey(c *gin.Context) {
	secKey, ok := c.GetPostForm(CONFIG_API_KEY_SECKEY)
	if !ok {
		c.String(400, "Not contained a sec key")
		return
	}

	if C.secKeyDigest != "" {
		digest := C.generateKeyDigest(secKey)
		if digest != C.secKeyDigest {
			c.String(400, "sec key is not matched")
			return
		}
		util.MaoLogM(util.INFO, MODULE_NAME, "Succeed to unlock the sec key")
	} else {
		util.MaoLogM(util.INFO, MODULE_NAME, "Setting a new sec key")
	}

	C.secKey = secKey
	C.secKeyDigest = C.generateKeyDigest(secKey)

	// write C.secKeyDigest to file
	C.PutConfig(CONFIG_PATH_SEC_KEY_DIGEST, C.secKeyDigest)

	C.publishKeyUpdate()
}


func (C *ConfigYamlModule) InitConfigModule(configFilename string) bool {
	C.configFilename = configFilename
	C.needShutdown = false

	// support custom size for the channel.

	if C.eventChannel == nil  {
		C.eventChannel = make(chan *configEvent, 100)
	}

	if C.keyUpdateListeners == nil {
		C.keyUpdateListeners = make([]*chan int, 0)
	}


	if fileIsNotExist(C.configFilename) {
		util.MaoLogM(util.WARN, MODULE_NAME, "config file not found, creating it.")
		_, err := os.Create(C.configFilename)
		if err != nil {
			util.MaoLogM(util.ERROR, MODULE_NAME, "Fail to create config file. (%s)", err.Error())
			return false
		}
	}

	config, err := C.loadConfig()
	if err != nil {
		util.MaoLogM(util.ERROR, MODULE_NAME, "ConfigModule: Fail to load config, err: %s", err.Error())
		return false
	}

	C.configRestControlInterface()

	go C.eventLoop(config)


	secKey, errCode := C.GetConfig(CONFIG_PATH_SEC_KEY_DIGEST)
	if errCode == ERR_CODE_SUCCESS {
		var ok bool
		C.secKeyDigest, ok = secKey.(string)
		if !ok {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail, the secKeyDigest is not a string")
		}
	} else if errCode != ERR_CODE_PATH_TRANSIT_FAIL && errCode != ERR_CODE_PATH_NOT_EXIST {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to read secKey config, code: %d", errCode)
	}

	return true
}
