package MaoCloudMonitor

import (
	"MaoServerDiscovery/cmd/lib/MaoCommon"
	"MaoServerDiscovery/util"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strings"
)

const (
	MODULE_NAME                    = "Mao-Cloud-Monitor"
	URL_MAOCLOUD_MERGE_ALL_STATION = "/getMaoCloudMergeAllStation"
)

type MaoCloudMonitorWrapper struct {
}

func (mw *MaoCloudMonitorWrapper) InitMaoCloudMonitorWrapper() {
	mw.configRestControlInterface()
}

func (mw *MaoCloudMonitorWrapper) configRestControlInterface() {
	restfulServer := MaoCommon.ServiceRegistryGetRestfulServerModule()
	if restfulServer == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get RestfulServerModule, unable to register restful apis.")
		return
	}

	restfulServer.RegisterGetApi(URL_MAOCLOUD_MERGE_ALL_STATION, mw.getMergeAllStation)
}

func getRemoteStationInfo(station_monitor_url string) (string, error) {
	resp, err := http.Get(station_monitor_url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func convertStationInfoToMap(info string) map[string]interface{} {

	data := make(map[string]interface{})

	items := strings.Split(info, ";")
	for _, item := range items {
		kv := strings.Split(item, "=")
		if len(kv) == 2 {
			data[kv[0]] = kv[1]
		}
	}

	return data
}

func (mw *MaoCloudMonitorWrapper) getMergeAllStation(c *gin.Context) {

	demo_station_list := []string{}

	data_list := make([]interface{}, 0)

	for _, station := range demo_station_list {
		info, _ := getRemoteStationInfo(station)
		station_map := convertStationInfoToMap(info)
		data_list = append(data_list, station_map)
	}

	data := make(map[string]interface{})
	data["stations"] = data_list

	// Attention: password can't be outputted !!!
	c.JSON(200, data)
}
