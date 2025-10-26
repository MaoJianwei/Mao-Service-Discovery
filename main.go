package main

import (
	branch "MaoServerDiscovery/cmd"
	"MaoServerDiscovery/util"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"
	"runtime"
	"strings"

	"net/http"
	_ "net/http/pprof"
)

const (
        ROOT_VERSION = "2.0"
	// GENERAL_CLIENT_VERSION = "1.6"
	// SERVER_VERSION = "1.6"
	// ROOT_VERSION_SIGNATURE = "\nServer: " + SERVER_VERSION + " Client: " + GENERAL_CLIENT_VERSION + "\nGit: " + GIT_VERSION
)

/*
	Steps to add a new parameter:
	1. Add a global variant
	2. Register the parameter and some introductions in the init()
	3. Add a reader and some checking rules of the parameter in something like readServerArgs()
	4. Add the global variant in the module entry like branch.RunServer()
	5. Add some introductions for the parameter before the init()
 */

var (
        GIT_VERSION = "Not set during the link time."
        ROOT_VERSION_SIGNATURE = ROOT_VERSION + "\nCode Version: " + GIT_VERSION

	//main_server_addr net.IP
	report_server_addr net.IP
	report_server_port uint32
	minLogLevel util.MaoLogLevel
	silent bool


	web_server_addr net.IP
	web_server_port uint32

	cli_dump_interval uint32
	refresh_interval uint32


	report_interval uint32

	nat66Gateway bool
	nat66Persistent bool

	gpsMonitor bool
	gpsPersistent bool

	influxdbUrl string
	influxdbOrgBucket string
	influxdbToken string

	disable_gateway_module bool

	envTempMonitor bool
	envTempPersistent bool
)

var rootCmd = &cobra.Command{
	Use: "MaoServerDiscovery",
	Short:   "Mao-Service-Discovery, welcome to join our Github community. https://github.com/MaoJianwei/Mao_Service_Discovery",
	Long:    "Mao-Service-Discovery:\nService registry & Service discovery & Service keep-alive.\nWelcome to join our Github community. https://github.com/MaoJianwei/MaoServiceDiscovery",
	Version: ROOT_VERSION_SIGNATURE,
	Run: func(cmd *cobra.Command, args []string) {
		if err := cmd.Help(); err != nil {
			util.MaoLog(util.ERROR, "Fail to execute rootCmd.Help(): %s", err.Error())
		}
	},
}

var generalClientCmd = &cobra.Command{
	Use: "client",
	Short:   "Mao: Run general client. For common device, server, PC, laptop, Raspberry Pi, etc.",
	Long:    "Mao-Service-Discovery:\nRun general client. For common device, server, PC, laptop, Raspberry Pi, etc.",
	// Version: GENERAL_CLIENT_VERSION,
	Run: func(cmd *cobra.Command, args []string) {
		if err := readGeneralClientArgs(cmd); err != nil {
			util.MaoLog(util.ERROR, "Wrong Args for general client: %s", err.Error())
			return
		}

		if nat66Gateway == true {
			if runtime.GOOS != `linux` || os.Getgid() != 0 {
				util.MaoLog(util.ERROR, "nat66Gateway is usable only in linux with root privilege")
				return
			}
		}

		client := &branch.GeneralClientV2{}
		client.Run(&report_server_addr, report_server_port, report_interval, silent,
			influxdbUrl, influxdbOrgBucket, influxdbToken,
			nat66Gateway, nat66Persistent, gpsMonitor, gpsPersistent, envTempMonitor, envTempPersistent,
			minLogLevel)

		//branch.RunGeneralClient(&report_server_addr, report_server_port, report_interval, silent,
		//	influxdbUrl, influxdbOrgBucket, influxdbToken,
		//	nat66Gateway, nat66Persistent, gpsMonitor, gpsPersistent, envTempMonitor, envTempPersistent,
		//	minLogLevel)
	},
}

var serverCmd = &cobra.Command{
	Use: "server",
	Short:   "Mao: Run server.",
	Long:    "Mao-Service-Discovery: Run server.",
	// Version: SERVER_VERSION,
	Run: func(cmd *cobra.Command, args []string) {
		if err := readServerArgs(cmd); err != nil {
			util.MaoLog(util.ERROR, "Wrong Args for server: %s", err.Error())
			return
		}

		//ss,_ := rootCmd.PersistentFlags().GetString("report_server_addr")
		//report_server_addr = net.ParseIP(ss)
		//fmt.Printf("%v\n%v\n%v\n%v\n%v\n%v\n%v\n",
		//	report_server_addr,
		//	report_server_port,
		//	main_server_addr,
		//	web_server_addr,
		//	web_server_port,
		//	cli_dump_interval,
		//	report_interval)
		//
		//fmt.Printf("---\n%v, %d\n", args, len(args))
		//return
		branch.RunServer(&report_server_addr, report_server_port, &web_server_addr, web_server_port,
			influxdbUrl, influxdbToken, influxdbOrgBucket,
			cli_dump_interval, refresh_interval, minLogLevel, silent,
			disable_gateway_module, ROOT_VERSION)
	},
}

var versionCmd = &cobra.Command{
	Use: "version",
	Short:   "Mao: Show software version and code version.",
	Long:    "Mao-Service-Discovery: Show software version and code version.",
	// Version: SERVER_VERSION,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("MaoServerDiscovery version " + ROOT_VERSION_SIGNATURE)
	},
}

/**
Common:
	- report_server_addr : connect to / listen on the addr, for service discovery
	- report_server_port : connect to / listen on the port, for service discovery
	- log : min log level. If set to INFO, DEBUG log will not be outputted.
	- silent : if true, no log will be outputted. prior to the log parameter.
Server:
	- web_server_addr : listen on the addr, for web control
	- web_server_port : listen on the port, for web control

	- cli_dump_interval : interval for dump all services info. (milliseconds)
	//- refresh_interval : interval for refresh the status of clients. (milliseconds)

Client:
	- report_interval : interval for report status to server. (milliseconds)

	- influxdb_url ：url to access influxdb database
	- influxdb_org_bucket : organization and bucket names
	- influxdb_token : token to access influxdb database

	- enable_aux_nat66_stat : enable to pull statistics of nat66 gateway
	- enable_aux_nat66_persistent : enable to persistent nat66 statistics to database

	- enable_gps_monitor : enable to read GPS data via serial port from the GPS module
	- enable_gps_persistent : enable to persistent GPS statistics to database

	- enable_aux_env_temp_monitor : enable to monitor environment temperature
	- enable_aux_env_temp_persistent : enable to upload environment temperature to Influxdb
 */
func init() {
	rootCmd.PersistentFlags().String("report_server_addr","::","IP address for gRPC KA module. (e.g. 2001:db8::1)")
	rootCmd.PersistentFlags().Uint32("report_server_port",28888,"Port for gRPC KA module.")
	rootCmd.PersistentFlags().String("log_level", "INFO","The min level for the logs outputted. (e.g. DEBUG, INFO, WARN, ERROR, SILENT)")
	rootCmd.PersistentFlags().Bool("silent", false,"Don't output the server list periodically. (default: false)")


	//serverCmd.Flags().String("main_server_addr","::","::")
	serverCmd.Flags().String("web_server_addr","::","IP address for Restful server.")
	serverCmd.Flags().Uint32("web_server_port",29999,"Port for Restful server.")

	serverCmd.Flags().Uint32("cli_dump_interval", 1000, "The interval to output all services info to the CLI, in milliseconds.")
	//serverCmd.Flags().Uint32("refresh_interval", 1000, "The interval to refresh the status of clients, in milliseconds.")

	serverCmd.Flags().String("influxdb_url","","URL for connecting to Influxdb. (e.g. https://<domain-or-ip>:<port>) (Optional)")
	serverCmd.Flags().String("influxdb_org_bucket","","Same name for Org and Bucket. (Optional)")
	serverCmd.Flags().String("influxdb_token","","Token string obtained from Influxdb. (Optional)")

	serverCmd.Flags().Bool("disable_gateway_module",false,"Disable all Gateway modules. (Optional) (default: false)")


	generalClientCmd.Flags().Uint32("report_interval", 1000, "The interval to collect data and report to server, in milliseconds.")

	generalClientCmd.Flags().String("influxdb_url","","URL for connecting to Influxdb. (e.g. https://<domain-or-ip>:<port>) (Optional)")
	generalClientCmd.Flags().String("influxdb_org_bucket","","Same name for Org and Bucket. (Optional)")
	generalClientCmd.Flags().String("influxdb_token","","Token string obtained from Influxdb. (Optional)")

	generalClientCmd.Flags().Bool("enable_aux_nat66_stat", false, "Enable to pull statistics of nat66 gateway. Usable only in linux with root privilege. (default: false)")
	generalClientCmd.Flags().Bool("enable_aux_nat66_persistent", false, "Enable to upload nat66 stat to Influxdb. (default: false)")

	generalClientCmd.Flags().Bool("enable_gps_monitor", false, "Enable to read GPS data via serial port from the GPS module. (default: false)")
	generalClientCmd.Flags().Bool("enable_gps_persistent", false, "Enable to upload GPS data to Influxdb. (default: false)")

	generalClientCmd.Flags().Bool("enable_aux_env_temp_monitor", false, "Enable to monitor environment temperature. (default: false)")
	generalClientCmd.Flags().Bool("enable_aux_env_temp_persistent", false, "Enable to upload environment temperature to Influxdb. (default: false)")
}

func readRootArgs(cmd *cobra.Command) error {

	report_server_addr_str, err := rootCmd.PersistentFlags().GetString("report_server_addr")
	if err != nil {
		return err
	}
	report_server_addr = net.ParseIP(report_server_addr_str)
	if report_server_addr == nil {
		return errors.New("report_server_addr is invalid")
	}

	report_server_port, err = rootCmd.PersistentFlags().GetUint32("report_server_port")
	if err != nil {
		return err
	}
	if report_server_port < 1 || report_server_port > 65535 {
		return errors.New("report_server_port is invalid")
	}

	min_log_level, err := rootCmd.PersistentFlags().GetString("log_level")
	if err != nil {
		return err
	}
	found := false
	for i, s := range util.MaoLogLevelString {
		if strings.Contains(s, min_log_level) {
			minLogLevel = util.MaoLogLevel(i)
			found = true
			break
		}
	}
	if !found {
		return errors.New("log_level is invalid")
	}

	silent, err = rootCmd.PersistentFlags().GetBool("silent")
	if err != nil {
		return err
	}

	return nil
}

func readServerArgs(cmd *cobra.Command) error {

	if err := readRootArgs(cmd); err != nil {
		return err
	}

	//main_server_addr_str, err := cmd.Flags().GetString("main_server_addr")
	//if err != nil {
	//	return err
	//}
	//main_server_addr = net.ParseIP(main_server_addr_str)
	//if main_server_addr == nil {
	//	return errors.New("main_server_addr is invalid")
	//}

	web_server_addr_str, err := cmd.Flags().GetString("web_server_addr")
	if err != nil {
		return err
	}
	web_server_addr = net.ParseIP(web_server_addr_str)
	if web_server_addr == nil {
		return errors.New("web_server_addr is invalid")
	}

	web_server_port, err = cmd.Flags().GetUint32("web_server_port")
	if err != nil {
		return err
	}
	if web_server_port < 1 || web_server_port > 65535 {
		return errors.New("web_server_port is invalid")
	}


	cli_dump_interval, err = cmd.Flags().GetUint32("cli_dump_interval")
	if err != nil {
		return err
	}
	if cli_dump_interval < 1 {
		return errors.New("cli_dump_interval is invalid")
	}

	//refresh_interval, err = cmd.Flags().GetUint32("refresh_interval")
	//if err != nil {
	//	return err
	//}
	//if refresh_interval < 1 {
	//	return errors.New("refresh_interval is invalid")
	//}
	refresh_interval = 1000 // deprecated and useless, this is a padding. can be deleted.

	influxdbUrl, err = cmd.Flags().GetString("influxdb_url")
	if err != nil {
		return err
	}

	influxdbOrgBucket, err = cmd.Flags().GetString("influxdb_org_bucket")
	if err != nil {
		return err
	}

	influxdbToken, err = cmd.Flags().GetString("influxdb_token")
	if err != nil {
		return err
	}

	disable_gateway_module, err = cmd.Flags().GetBool("disable_gateway_module")
	if err != nil {
		return err
	}

	return nil
}

func readGeneralClientArgs(cmd *cobra.Command) error {

	if err := readRootArgs(cmd); err != nil {
		return err
	}

	var err error
	report_interval, err = cmd.Flags().GetUint32("report_interval")
	if err != nil {
		return err
	}
	if report_interval < 1 {
		return errors.New("report_interval is invalid")
	}


	influxdbUrl, err = cmd.Flags().GetString("influxdb_url")
	if err != nil {
		return err
	}

	influxdbOrgBucket, err = cmd.Flags().GetString("influxdb_org_bucket")
	if err != nil {
		return err
	}

	influxdbToken, err = cmd.Flags().GetString("influxdb_token")
	if err != nil {
		return err
	}


	nat66Gateway, err = cmd.Flags().GetBool("enable_aux_nat66_stat")
	if err != nil {
		return err
	}

	nat66Persistent, err = cmd.Flags().GetBool("enable_aux_nat66_persistent")
	if err != nil {
		return err
	}


	gpsMonitor, err = cmd.Flags().GetBool("enable_gps_monitor")
	if err != nil {
		return err
	}

	gpsPersistent, err = cmd.Flags().GetBool("enable_gps_persistent")
	if err != nil {
		return err
	}


	envTempMonitor, err = cmd.Flags().GetBool("enable_aux_env_temp_monitor")
	if err != nil {
		return err
	}

	envTempPersistent, err = cmd.Flags().GetBool("enable_aux_env_temp_persistent")
	if err != nil {
		return err
	}


	if (envTempPersistent || nat66Persistent) && influxdbUrl == "" {
		return errors.New("influxdb_url is invalid")
	}
	if (envTempPersistent || nat66Persistent) && influxdbOrgBucket == "" {
		return errors.New("influxdb_org_bucket is invalid")
	}
	if (envTempPersistent || nat66Persistent) && influxdbToken == "" {
		return errors.New("influxdb_token is invalid")
	}

	return nil
}


func main() {
	go func() {
	   util.MaoLog(util.INFO, "enable pprof: %v", http.ListenAndServe("0.0.0.0:39999", nil))
	}()

	rootCmd.AddCommand(versionCmd, generalClientCmd, serverCmd)

	if err := rootCmd.Execute(); err != nil {
		//util.MaoLog(util.ERROR, fmt.Sprintf("Fail to execute rootCmd: %s", err))
		os.Exit(-1)
	}
}

