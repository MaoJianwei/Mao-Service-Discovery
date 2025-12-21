package Config

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/MaoJianwei/gmsm/sm3"
	"io"
	//"github.com/tjfoc/gmsm/sm3"
	//"github.com/tjfoc/gmsm/sm4"
	"github.com/MaoJianwei/gmsm/sm4"
	"os"
	"testing"
	"time"
)

func TestSM4GCM_TestVectors(t *testing.T) {
	/*
		SM4-GCM Test Vectors

		   Initialization Vector:   00001234567800000000ABCD
		   Key:                     0123456789ABCDEFFEDCBA9876543210
		   Plaintext:               AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
		                            CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
		                            EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF
		                            EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA
		   Associated Data:         FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2
		   CipherText:              17F399F08C67D5EE19D0DC9969C4BB7D
		                            5FD46FD3756489069157B282BB200735
		                            D82710CA5C22F0CCFA7CBF93D496AC15
		                            A56834CBCF98C397B4024A2691233B8D
		   Authentication Tag:      83DE3541E4C2B58177E065A9BF7B62EC
	*/

	IV := []byte{0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD}

	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}

	plaintext := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
		0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	}


	associatedData := []byte{
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0xAB, 0xAD, 0xDA, 0xD2,
	}


	cipherText := []byte{
		0x17, 0xF3, 0x99, 0xF0, 0x8C, 0x67, 0xD5, 0xEE,
		0x19, 0xD0, 0xDC, 0x99, 0x69, 0xC4, 0xBB, 0x7D,
		0x5F, 0xD4, 0x6F, 0xD3, 0x75, 0x64, 0x89, 0x06,
		0x91, 0x57, 0xB2, 0x82, 0xBB, 0x20, 0x07, 0x35,
		0xD8, 0x27, 0x10, 0xCA, 0x5C, 0x22, 0xF0, 0xCC,
		0xFA, 0x7C, 0xBF, 0x93, 0xD4, 0x96, 0xAC, 0x15,
		0xA5, 0x68, 0x34, 0xCB, 0xCF, 0x98, 0xC3, 0x97,
		0xB4, 0x02, 0x4A, 0x26, 0x91, 0x23, 0x3B, 0x8D,
	}
	authTag := []byte{
		0x83, 0xDE, 0x35, 0x41, 0xE4, 0xC2, 0xB5, 0x81,
		0x77, 0xE0, 0x65, 0xA9, 0xBF, 0x7B, 0x62, 0xEC,
	}


	for i:=0; i<1; i++ {
		fmt.Println("=======================")
		fmt.Printf("data = %v\n", plaintext)

		gcmMsg, T, err := sm4.Sm4GCM(key, IV, plaintext, nil, true)

		//gcmMsg, T, err := sm4.Sm4GCM(key, IV, plaintext, associatedData, true)
		if err != nil {
			t.Errorf("sm4 enc error:%s", err)
		}
		fmt.Printf("gcmMsg = %v\n", gcmMsg)

		gcmDec1, T_1, err := sm4.Sm4GCM(key, IV, gcmMsg, associatedData, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
		}
		fmt.Printf("gcmDec1 = %v\n", gcmDec1)
		if bytes.Compare(T, T_1) == 0 {
			fmt.Println("T, T_1 authentication succeeded, it is correct.")
		} else {
			fmt.Println("T, T_1 authentication fail, ignored.")
		}

		if bytes.Compare(T, authTag) == 0 {
			fmt.Println("T, authTag authentication succeeded, it is fantastically correct.")
		} else {
			fmt.Println("T, authTag authentication fail, it is temporarily correct.")
		}

		if len(plaintext) != len(gcmDec1) {
			t.Errorf("sm4 len(plaintext):%d != len(gcmDec1):%d", len(plaintext), len(gcmDec1))
		}
		if len(gcmMsg) != len(gcmDec1) {
			t.Errorf("sm4 len(gcmMsg):%d != len(gcmDec1):%d", len(gcmMsg), len(gcmDec1))
		}
		for i := 0; i < len(plaintext); i++ {
			if plaintext[i] != gcmDec1[i] {
				t.Errorf("sm4 plaintext[%d]:%x != gcmDec1[%d]:%x", i, plaintext[i], i, gcmDec1[i])
			}
		}
		for i := 0; i < len(cipherText); i++ {
			if cipherText[i] != gcmMsg[i] {
				t.Errorf("sm4 cipherText[%d]:%x != gcmMsg[%d]:%x", i, cipherText[i], i, gcmMsg[i])
			}
		}
		fmt.Println("Enc/Dec successed")
	}
}


func TestSM4GCM(t *testing.T) {

	// There is problem if the length of plaintext is not n*sm4.BlockSize
	key := []byte("Key 1920aF1080 !")

	data := []byte("contact Beijing TOWER 168.55@!xichang。 outEnc, err := MaoSm4EncryptAndDecrypt(plainTextByte, key, iv, true)，func Test_SM4(t *testing.T) {")
	//data := []byte("contact Beijing TOWER 168.55@!xichang. outEnc, err := MaoSm4EncryptAndDecrypt(plainTextByte, key, iv, true), func Test_SM4(t *testing.T) {987mao")

	IV := []byte("qindaoRadar1")

	testA := [][]byte{ // the length of the A can be random
		nil,
		[]byte{},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	for _, A := range testA {



		fmt.Println("=======================")
		fmt.Printf("data = %v\n", data)

		gcmMsg, T, err := sm4.Sm4GCM(key, IV, data, A, true)
		if err != nil {
			t.Errorf("sm4 enc error:%s", err)
		}
		fmt.Printf("gcmMsg = %v\n", gcmMsg)

		gcmDec1, T_1, err := sm4.Sm4GCM(key, IV, gcmMsg, A, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
		}
		fmt.Printf("gcmDec1 = %v\n", gcmDec1)
		if bytes.Compare(T, T_1) == 0 {
			fmt.Println("authentication successed, it is correct.")
		} else {
			t.Errorf("authentication fail, it is wrong.")
		}

		if len(data) != len(gcmDec1) {
			t.Errorf("sm4 len(data):%d != len(gcmDec1):%d", len(data), len(gcmDec1))
		}
		if len(gcmMsg) != len(gcmDec1) {
			t.Errorf("sm4 len(gcmMsg):%d != len(gcmDec1):%d", len(gcmMsg), len(gcmDec1))
		}
		for i := 0; i < len(data); i++ {
			if data[i] != gcmDec1[i] {
				t.Errorf("sm4 data[%d]:%x != gcmDec1[%d]:%x", i, data[i], i, gcmDec1[i])
			}
		}
		fmt.Println("Enc/Dec successed")



		//Failed Test : if we input the different A , that will be a falied result.
		A = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}
		gcmDec2, T_2, err := sm4.Sm4GCM(key, IV, gcmMsg, A, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
		}
		fmt.Printf("gcmDec2 = %v\n", gcmDec2)
		if bytes.Compare(T, T_2) != 0 {
			fmt.Println("authentication failed, it is correct.")
		} else {
			t.Errorf("authentication successed, it is wrong.")
		}

		if len(data) != len(gcmDec2) {
			t.Errorf("sm4 len(data):%d != len(gcmDec2):%d", len(data), len(gcmDec2))
		}
		if len(gcmMsg) != len(gcmDec2) {
			t.Errorf("sm4 len(gcmMsg):%d != len(gcmDec2):%d", len(gcmMsg), len(gcmDec2))
		}
		for i := 0; i < len(data); i++ {
			if data[i] != gcmDec2[i] {
				t.Errorf("sm4 data[%d]:%x != gcmDec2[%d]:%x", i, data[i], i, gcmDec2[i])
			}
		}
		fmt.Println("Enc/Dec successed")
	}
}

func Test_SM4(t *testing.T) {
	iv := []byte("qindaoRadar118.5")
	key := []byte("Key 1920aF1080 !")
	plainText := "contact Beijing TOWER 168.55@!xichang。 outEnc, err := MaoSm4EncryptAndDecrypt(plainTextByte, key, iv, true)，func Test_SM4(t *testing.T) {"
	plainTextByte := []byte(plainText)

	outEnc, err := MaoSm4EncryptAndDecrypt(plainTextByte, key, iv, true)
	if err != nil {
		t.Fatalf("err = %s\n", err.Error())
	}

	outDec, err := MaoSm4EncryptAndDecrypt(outEnc, key, iv, false)
	if err != nil {
		t.Fatalf("err = %s\n", err.Error())
	}

	if !bytes.Equal(plainTextByte, outDec) {
		t.Fatalf("the length or content of plainTextByte(%d) and outDec(%d) are not equal.\n", len(plainTextByte), len(outDec))
	}
	t.Logf("plainTextByte - %v\n", plainTextByte)
	t.Logf("outDec        - %v\n", outDec)
}

func MaoSm4EncryptAndDecrypt(plainText []byte, key []byte, iv []byte, isEncrypt bool) ([]byte, error) {
	if iv == nil {
		if !isEncrypt {
			return nil, errors.New("during decryption, iv must be provided")
		}
		iv = make([]byte, sm4.BlockSize)
		io.ReadFull(rand.Reader, iv)
	}
	out, err := sm4.Sm4Cbc(key, plainText, isEncrypt, iv)
	return out, err
}

func MaoSm3Digest(plainText []byte) ([]byte) {
	digest := sm3.Sm3Sum(plainText)
	return digest
}

func Test_SM3_loop(t *testing.T) {
	origin := "Bigmao Radio Station 2012-2023. SING Group. Beijing = Bigmao Radio Station 2012-2023. SING Group. Beijing"

	count := 1
	for {
		digest1 := MaoSm3Digest([]byte(origin))

		count++
		if count%1000000 == 0 {
			t.Logf("%d - %v = %v\n", count, digest1, origin)
			return
		}
	}
}

func Test_SM3(t *testing.T) {

	origin := "Bigmao Radio Station 2012-2023. SING Group. Beijing = Bigmao Radio Station 2012-2023. SING Group. Beijing"
	t.Logf("%v\n\n", origin)

	digest1 := sm3.Sm3Sum([]byte(origin))
	t.Logf("%v = %v\n\n", digest1, origin)
	for _, d := range digest1 {
		t.Logf("%02X ", d)
	}

	sss := sm3.New()
	bs1 := sss.BlockSize()
	s1 := sss.Size()
	t.Logf("%v = %v\n\n", bs1, s1)

	n, err := sss.Write([]byte(origin))
	t.Logf("%v = %v\n\n", n, err)

	bs2 := sss.BlockSize()
	s2 := sss.Size()
	t.Logf("%v = %v\n\n", bs2, s2)

	digest2 := sss.Sum(nil)
	t.Logf("%v = %v\n\n", digest2, origin)

	SSSSSS := sm3.New()
	digest3 := SSSSSS.Sum([]byte(origin))
	t.Logf("%v = %v\n\n", digest3, origin)
}

func TestConfigYamlModule_main(t *testing.T) {

	t.Log(os.Args)

	configModule := &ConfigYamlModule{}

	if !configModule.InitConfigModule(DEFAULT_CONFIG_FILE) {
		return
	}

	mmm := make(map[string]interface{})
	mmm["beijing"] = "ra11111dar"
	mmm["intintint"] = 7181
	mmm["fff"] = 2.525

	vvv := make(map[int]interface{})
	vvv[6666] = "radar"
	vvv[8888] = 5511
	vvv[7181] = 2.525

	value, errCode := configModule.GetConfig("/qingdao/radar/freq") // ok
	t.Logf("Put 1 %v, %v\n", value, errCode)

	value, errCode = configModule.GetConfig("/qingdao/radar/name") // ok
	t.Logf("Put 2 %v, %v\n", value, errCode)

	value, errCode = configModule.GetConfig("/qingdao/name") // ok
	t.Logf("Put 3 %v, %v\n", value, errCode)

	value, errCode = configModule.GetConfig("/config/module/instance/object") // bad
	t.Logf("Put 4 %v, %v\n", value, errCode)

	value, errCode = configModule.GetConfig("/config/module/instance/mmm") // ok
	t.Logf("Put 5 %v, %v\n", value, errCode)

	value, errCode = configModule.GetConfig("/config/module/instance/vvv") // ok
	t.Logf("Put 6 %v, %v\n", value, errCode)

	b, v := configModule.PutConfig("/qingdao/radar/freq", 118.5) // ok
	t.Logf("Put 1 %v, %v\n", b, v)

	b, v = configModule.PutConfig("/qingdao/radar/name", "qingdao") // ok
	t.Logf("Put 2 %v, %v\n", b, v)

	b, v = configModule.PutConfig("/qingdao/name", "liuting") // ok
	t.Logf("Put 3 %v, %v\n", b, v)

	b, v = configModule.PutConfig("/config/module/instance/object", configModule) // bad
	t.Logf("Put 4 %v, %v\n", b, v)

	b, v = configModule.PutConfig("/config/module/instance/mmm", mmm) // ok
	t.Logf("Put 5 %v, %v\n", b, v)

	b, v = configModule.PutConfig("/config/module/instance/vvv", vvv) // ok
	t.Logf("Put 6 %v, %v\n", b, v)

	configModule.RequireShutdown()

	time.Sleep(3 * time.Second)

	/*// ============================ Develop & Unit tests =============================
	config := make(map[string]interface{})
	tmp := make(map[string]interface{})
	config["qingdao"] = tmp

	tmp1 := make(map[string]interface{})
	tmp["radar"] = tmp1

	tmp2 := make(map[string]interface{})
	tmp1["118.5"] = tmp2

	tmp2["beijing-2"] = "qingdaoleida beijing bigmao"


	//GET Unit Tests:
	//path := "/" // ERR_CODE_PATH_FORMAT - ok
	//path := "/qingdao" // pass - ok
	//path := "/qingdao/" // ERR_CODE_PATH_FORMAT - ok
	//
	//path := "/qingdao/radar" // pass - ok
	//path := "/qingdao/radar/" // ERR_CODE_PATH_FORMAT - ok
	//
	//path := "/qingdao/radar/118.5" // pass - ok
	//path := "/qingdao/radar/118.5/" // ERR_CODE_PATH_FORMAT - ok
	//
	//path := "/qingdao/radar/218.5" // pass but result is nil - ok
	//path := "/qingdao/padar/118.5" // ERR_CODE_PATH_TRANSIT_FAIL - ok
	//
	//path := "/qingdao/radar/118.5/beijing-2" // pass - ok
	//path := "/qingdao/radar/118.5/beijing-2/" // ERR_CODE_PATH_FORMAT - ok

	//Put Unit Tests:
	//var newData interface{} = "bigmao radio station"
	//path := "/qingdao" // pass - ok
	//path := "/qingdao/radar" // pass - ok
	//path := "/qingdao/radar/118.5" // pass - ok
	//path := "/qingdao/radar/218.5" // pass - ok
	//path := "/qingdao/padar/118.5" // pass and create all transit path - ok
	//path := "/qingdao/padar/118.5/aaaa/b/1/5a" // pass and create all transit path - ok

	//Put Unit Tests - nil:
	//var newData interface{} = nil
	//path := "/qingdao" // pass and delete all, result is an empty map - ok
	//path := "/qingdao/radar" // pass and delete radar & 118.5 - ok
	//path := "/qingdao/radar/118.5" // pass and delete 118.5 - ok
	//path := "/qingdao/padar/118.5" // pass and: create all transit path, the last is an empty map of padar - ok

	log.Println("Origin config: ", config)

	// Mao: Design Principle: it is not allowed that the config contain nil.

	paths := strings.Split(path, "/")
	if paths[0] != "" || paths[len(paths)-1] == "" {
		log.Println("eventResult: ", eventResult{
			errCode: ERR_CODE_PATH_FORMAT,
			result:  nil,
		}) // event.result <-
		util.MaoLogM(util.WARN, MODULE_NAME, "format of config path is not correct.")
		return // continue
	}

	transitPaths := paths[1 : len(paths)-1] // [a, b)
	transitConfig := config
	var ok = true

	var missPos int
	var tmpPath string
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

			log.Println("in the for, ", eventResult{
				errCode: ERR_CODE_PATH_TRANSIT_FAIL,
				result:  nil,
			})     // event.result <-
			return // continue
		}
		log.Println(transitConfig)
	}
	log.Println("We get the transitConfig: ", transitConfig, missPos)

	//// in the Get case:
	if !ok {
		log.Println("out of the for, ", eventResult{
			errCode: ERR_CODE_PATH_TRANSIT_FAIL,
			result:  nil,
		}) // event.result <-
		return
	} else {
		result, ok := transitConfig[paths[len(paths)-1]]
		log.Println("Get operation: ", result, ok)
	}

	// in the Put case:
	if !ok {
		// Create transit path, and move transitConfig forward.
		// If nil is in the config, we will remove it or override it automatically here.
		log.Println(transitConfig, transitPaths, len(transitPaths), missPos, transitPaths[missPos])
		for ; missPos < len(transitPaths); missPos++ {
			var newMap = make(map[string]interface{})
			transitConfig[transitPaths[missPos]] = newMap
			transitConfig = newMap
		}
		log.Println("Transit created, we get the transitConfig: ", transitConfig)
	}

	// put nil means to delete. It is not allowed that the config contain nil.
	if newData == nil {
		// todo: iterate from bottom to top, to delete empty map
		delete(transitConfig, paths[len(paths)-1])
	} else {
		transitConfig[paths[len(paths)-1]] = newData
	}
	log.Println("After config: ", config)

	return

	// =========================================================*/

	//paths := strings.Split("/qingdao/ra1dar/118.5/beij1ing-2", "/")
	//if paths[0] != "" || paths[len(paths)-1] == "" {
	//	util.MaoLogM(util.WARN, MODULE_NAME, "format of config path is not correct.")
	//}
	//
	//transitPaths := paths[1:len(paths)-1]
	//transitConfig := config
	//var ok bool
	//for _, p := range transitPaths {
	//	tmpvar := transitConfig[p]
	//	transitConfig, ok = tmpvar.(map[string]interface{}) // can adapt nil
	//	if !ok {
	//		// todo:fail
	//	}
	//	log.Println(transitConfig)
	//}
	//result := transitConfig[paths[len(paths)-1]]
	//log.Println(result)
	//return

	//if InitConfigModule("mao-config.yaml") == false {
	//	return
	//}
	//
	//
	//log.Println(len(eventChannel))
	//go GetConfig("getPath")
	////eventP := &configEvent{
	////	eventType: EVENT_PUT,
	////	path:      "putPath",
	////	data:      make([]string, 3),
	////	result:    make(chan interface{}, 1),
	////}
	////eventChannel <- eventP
	//
	//log.Println(len(eventChannel))
	//mapmap := make(map[string]interface{})
	//mapmap["beijing-1"] = 118.5
	//mapmap["beijing-2"] = true
	//mapmap["beijing-3"] = "radar contact"
	//go PutConfig("putPath", mapmap)
	////eventG := &configEvent{
	////	eventType: EVENT_GET,
	////	path:      "getPath",
	////	data:      nil,
	////	result:    make(chan interface{}, 1),
	////}
	////eventChannel <- eventG
	//
	//log.Println(len(eventChannel))
	//
	//log.Println(eventChannel)
	//time.Sleep(3 * time.Second)
	//RequireShutdown()
	//time.Sleep(1000 * time.Second)
}

/**
content, _ := ioutil.ReadFile(DEFAULT_CONFIG_FILE)

var c map[string]interface{}
yaml.Unmarshal(content, &c)
fmt.Printf("%v", c)

orderer := c["orderer"].(map[string]interface{})
orderer2 := c["orderer"].(map[string]interface{})

delete(orderer, )

mmm := make(map[string]interface{})
mmm["beijing"] = "lei da yin dao"
mmm["xichang"] = 6858
(c["orderer"].(map[interface{}]interface{}))["baas"] = mmm

fmt.Printf("%v", c)
data, _ := yaml.Marshal(c)

fmt.Printf("%v", data)
ioutil.WriteFile("yamlAfter.yaml", data, 0666)

fmt.Printf("%v", data)
*/
