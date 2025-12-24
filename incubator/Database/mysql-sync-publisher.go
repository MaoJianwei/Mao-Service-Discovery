package MaoDatabase

import (
	"MaoServerDiscovery/cmd/lib/Config"
	"MaoServerDiscovery/cmd/lib/MaoCommon"
	"MaoServerDiscovery/util"
	"context"
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"strconv"
	"strings"
	"time"
)

const (
	MODULE_NAME = "MYSQL-DB-SYNC-incubator"
	MYSQL_DB_TABLE_CREATE_SQL =
		"create table if not exists MaoServiceDiscovery (" +
			"Service_IP nvarchar(1024)," +
			"Report_IP nvarchar(1024)," +
			"Alive BOOLEAN," +
			"Detect_Count BIGINT," +
			"Report_Count BIGINT," +
			"Last_Seen nvarchar(1024)," +
			"Rtt_Duration nvarchar(1024)," +
			"RttOutbound_or_Remote_Timestamp nvarchar(1024)," +
			"Aux_Data nvarchar(1024)," +
			"primary key (Service_IP)" +
		");"
	MYSQL_DB_DATA_INSERT_SQL =
		"insert into MaoServiceDiscovery (" +
			"Service_IP, Report_IP, Alive," +
			"Detect_Count, Report_Count," +
			"Last_Seen, Rtt_Duration, RttOutbound_or_Remote_Timestamp," +
			"Aux_Data" +
		") values (?, ?, ?, ?, ?, ?, ?, ?, ?);"
	MYSQL_DB_TABLE_CLEAR_SQL = "delete from MaoServiceDiscovery"

	URL_MYSQL_HOMEPAGE = "/configMysql"
	URL_MYSQL_CONFIG   = "/addMysqlInfo"
	URL_MYSQL_SHOW   = "/getMysqlInfo"

	MYSQL_INFO_CONFIG_PATH_ROOT = "/mysql"
	MYSQL_INFO_CONFIG_PATH_PASSWORD = "/mysql/password"

	MYSQL_CONFIG_KEY_SERVER_IP_DOMAIN_NAME = "ipDomainName"
	MYSQL_CONFIG_KEY_SERVER_PORT = "port"
	MYSQL_CONFIG_KEY_USERNAME = "username"
	MYSQL_CONFIG_KEY_DB_NAME  = "databaseName"

	MYSQL_API_KEY_SERVER_IP_DOMAIN_NAME = "mysqlServerAddr"
	MYSQL_API_KEY_SERVER_PORT = "mysqlServerPort"
	MYSQL_API_KEY_USERNAME = "username"
	MYSQL_API_KEY_PASSWORD = "password"
	MYSQL_API_KEY_DB_NAME = "databaseName"
)

type MysqlDataPublisher struct {

	username string
	password string
	ipDomainName string
	port uint16
	databaseName string

	// username:password@tcp(ipDomainName:port)/databaseName
	dataSourceName string

	secConfigChannel chan int

	dbConn *sql.DB
}



func (m *MysqlDataPublisher) initDatabaseTable() bool {

	dbTx, err := m.dbConn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to create a transaction, %s", err.Error())
		return false
	}

	result, err := dbTx.ExecContext(context.Background(), MYSQL_DB_TABLE_CREATE_SQL)
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to create the table: %s, %s", "MaoServiceDiscovery", err.Error())
		dbTx.Rollback()
		return false
	}

	lastInsertId, err := result.LastInsertId()
	rowsAffected, err := result.RowsAffected()
	util.MaoLogM(util.INFO, MODULE_NAME, "Create the table OK, %d, %d rows", lastInsertId, rowsAffected)

	err = dbTx.Commit()
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to commit the transaction, %s", err.Error())
		dbTx.Rollback()
		return false
	}

	return true
}

func (m *MysqlDataPublisher) databaseInsertServices(dbTx *sql.Tx) error {
	_, err := dbTx.ExecContext(context.Background(), MYSQL_DB_TABLE_CLEAR_SQL)
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to clear the table: %s, %s", "MaoServiceDiscovery", err.Error())
		return err
	}

	grpcKaModule := MaoCommon.ServiceRegistryGetGrpcKaModule()
	if grpcKaModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get GrpcKaModule")
	} else {
		serviceInfos := grpcKaModule.GetServiceInfo()
		for _, s := range serviceInfos {
			_, err := dbTx.ExecContext(context.Background(), MYSQL_DB_DATA_INSERT_SQL,
				s.Hostname, strings.Join(s.Ips, "\n"), s.Alive, 0, s.ReportTimes, s.LocalLastSeen, fmt.Sprintf("%.3fms", float64(s.RttDuration.Nanoseconds())/1000000), s.ServerDateTime, s.OtherData)
			if err != nil {
				return err
			}
		}
	}

	icmpKaModule := MaoCommon.ServiceRegistryGetIcmpKaModule()
	if icmpKaModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get IcmpKaModule")
	} else {
		serviceInfos := icmpKaModule.GetServices()
		for _, s := range serviceInfos {
			_, err := dbTx.ExecContext(context.Background(), MYSQL_DB_DATA_INSERT_SQL,
				s.Address, "/", s.Alive, s.DetectCount, s.ReportCount, s.LastSeen, fmt.Sprintf("%.3fms", float64(s.RttDuration.Nanoseconds())/1000000), s.RttOutboundTimestamp, "/")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *MysqlDataPublisher) databaseEventLoop() {
	updateInterval := time.Duration(1000) * time.Millisecond
	updateTimer := time.NewTimer(updateInterval)

	warnLogSuppress := false
	for {
		select {
		case <-m.secConfigChannel:
			m.loadMysqlSecConfig()
		case <-updateTimer.C:
			for {
				if m.dbConn == nil {
					break
				}

				dbTx, err := m.dbConn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
				if err != nil {
					if !warnLogSuppress {
						util.MaoLogM(util.WARN, MODULE_NAME, "Fail to create a transaction, %s", err.Error())
						warnLogSuppress = true
					}
					break
				}
				warnLogSuppress = false

				err = m.databaseInsertServices(dbTx)
				if err != nil {
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to insert data to the table: %s, %s", "MaoServiceDiscovery", err.Error())
					dbTx.Rollback()
					break
				}

				err = dbTx.Commit()
				if err != nil {
					util.MaoLogM(util.WARN, MODULE_NAME, "Fail to commit the transaction, %s", err.Error())
					dbTx.Rollback()
					break
				}

				break // this "for" runs just once. because we need to reset the timer.
			}
			updateTimer.Reset(updateInterval)
		}
	}
}

func (m *MysqlDataPublisher) configRestControlInterface() {
	restfulServer := MaoCommon.ServiceRegistryGetRestfulServerModule()
	if restfulServer == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get RestfulServerModule, unable to register restful apis.")
		return
	}

	restfulServer.RegisterUiPage(URL_MYSQL_HOMEPAGE, m.showMysqlPage)
	restfulServer.RegisterGetApi(URL_MYSQL_SHOW, m.showMysqlInfo)
	restfulServer.RegisterPostApi(URL_MYSQL_CONFIG, m.processMysqlInfo)
}

func (m *MysqlDataPublisher) showMysqlPage(c *gin.Context) {
	c.HTML(200, "index-mysql.html", nil)
}

func (m *MysqlDataPublisher) showMysqlInfo(c *gin.Context) {
	data := make(map[string]interface{})
	data[MYSQL_API_KEY_USERNAME] = m.username
	data[MYSQL_API_KEY_SERVER_IP_DOMAIN_NAME] = m.ipDomainName
	data[MYSQL_API_KEY_SERVER_PORT] = m.port
	data[MYSQL_API_KEY_DB_NAME] = m.databaseName

	// Attention: password can't be outputted !!!
	c.JSON(200, data)
}

func (m *MysqlDataPublisher) loadMysqlSecConfig() {
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return
	}

	password, errCode := configModule.GetSecConfig(MYSQL_INFO_CONFIG_PATH_PASSWORD)
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to read mysql config, code: %d, %v", errCode, errCode)
		return
	}

	var ok bool
	m.password, ok = password.(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse mysql config - password")
		return
	}

	util.MaoLogM(util.INFO, MODULE_NAME, "Loaded sec config")
	if !m.reConstructMysqlConnection() {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to re-construct MYSQL connection.")
	} else {
		util.MaoLogM(util.INFO, MODULE_NAME, "Connected to MYSQL database.")
	}
}

func (m *MysqlDataPublisher) loadMysqlConfig() {
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return
	}

	mysqlConfig, errCode := configModule.GetConfig(MYSQL_INFO_CONFIG_PATH_ROOT)
	if errCode != Config.ERR_CODE_SUCCESS {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to read mysql config, code: %d, %v", errCode, errCode)
		return
	}
	if mysqlConfig == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "There is no mysql config. You may need to config mysql module.")
		return
	}

	mysqlConfigMap, ok := mysqlConfig.(map[string]interface{})
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse mysql config, can't convert to map[string]interface{}")
		return
	}



	username, ok := mysqlConfigMap[MYSQL_CONFIG_KEY_USERNAME].(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse mysql config - %s", MYSQL_CONFIG_KEY_USERNAME)
		return
	}
	databaseName, ok := mysqlConfigMap[MYSQL_CONFIG_KEY_DB_NAME].(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse mysql config - %s", MYSQL_CONFIG_KEY_DB_NAME)
		return
	}
	mysqlServerAddr, ok := mysqlConfigMap[MYSQL_CONFIG_KEY_SERVER_IP_DOMAIN_NAME].(string)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse mysql config - %s", MYSQL_CONFIG_KEY_SERVER_IP_DOMAIN_NAME)
		return
	}
	mysqlServerPort, ok := mysqlConfigMap[MYSQL_CONFIG_KEY_SERVER_PORT].(int)
	if !ok {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to parse mysql config - %s", MYSQL_CONFIG_KEY_SERVER_PORT)
		return
	}

	m.username = username
	m.databaseName = databaseName
	m.ipDomainName = mysqlServerAddr
	m.port = uint16(mysqlServerPort)
}

func (m *MysqlDataPublisher) processMysqlInfo(c *gin.Context) {

	username, ok := c.GetPostForm(MYSQL_API_KEY_USERNAME)
	if !ok {
		c.String(200, "Fail to parse username.")
		return
	}

	password, ok := c.GetPostForm(MYSQL_API_KEY_PASSWORD)
	if !ok {
		c.String(200, "Fail to parse password.")
		return
	}

	mysqlServerAddr, ok := c.GetPostForm(MYSQL_API_KEY_SERVER_IP_DOMAIN_NAME)
	if !ok {
		c.String(200, "Fail to parse mysqlServerAddr.")
		return
	}

	mysqlServerPort, ok := c.GetPostForm(MYSQL_API_KEY_SERVER_PORT)
	var port64 uint64
	var err error
	if ok {
		port64, err = strconv.ParseUint(mysqlServerPort, 10, 16)
		if err != nil {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to update mysql config, port number is error, %s", err.Error())
			c.String(200, "Fail to update mysql config, port number is error, %s", err.Error())
			return
		}
	}

	databaseName, ok := c.GetPostForm(MYSQL_API_KEY_DB_NAME)
	if !ok {
		c.String(200, "Fail to parse databaseName.")
		return
	}

	m.username = username
	m.password = password
	m.ipDomainName = mysqlServerAddr
	m.port = uint16(port64)
	m.databaseName = databaseName

	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance, can't save mysql info")
	} else {
		data := make(map[string]interface{})
		data[MYSQL_CONFIG_KEY_USERNAME] = m.username
		data[MYSQL_CONFIG_KEY_SERVER_IP_DOMAIN_NAME] = m.ipDomainName
		data[MYSQL_CONFIG_KEY_SERVER_PORT] = m.port
		data[MYSQL_CONFIG_KEY_DB_NAME] = m.databaseName

		// Attention: password can't be outputted !!!
		configModule.PutConfig(MYSQL_INFO_CONFIG_PATH_ROOT, data)
		configModule.PutSecConfig(MYSQL_INFO_CONFIG_PATH_PASSWORD, m.password)
	}

	if !m.reConstructMysqlConnection() {
		c.String(200, "Fail to re-construct MYSQL connection.")
	} else {
		m.showMysqlPage(c)
		util.MaoLogM(util.INFO, MODULE_NAME, "Connected to MYSQL database.")
	}
}

func (m * MysqlDataPublisher) reConstructMysqlConnection() bool {
	m.dataSourceName = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", m.username, m.password, m.ipDomainName, m.port, m.databaseName)

	db, err := sql.Open("mysql", m.dataSourceName)
	if err != nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to open database connection, %s", err.Error())
		return false
	}

	if m.dbConn != nil {
		err = m.dbConn.Close()
		if err != nil {
			util.MaoLogM(util.WARN, MODULE_NAME, "Fail to close previous database connection, %s", err.Error())
		}
	}
	m.dbConn = db

	m.dbConn.SetConnMaxLifetime(0)
	m.dbConn.SetMaxOpenConns(60)
	m.dbConn.SetMaxIdleConns(60)

	return m.initDatabaseTable()
}

func (m *MysqlDataPublisher) registerSecConfigListener() {
	configModule := MaoCommon.ServiceRegistryGetConfigModule()
	if configModule == nil {
		util.MaoLogM(util.WARN, MODULE_NAME, "Fail to get config module instance")
		return
	}

	// register config-secKey listener
	configModule.RegisterKeyUpdateListener(&m.secConfigChannel)
}

func (m *MysqlDataPublisher) InitMysqlDataPublisher() bool {

	//todo: read MYSQL config from config file.
	//m.username = username
	//m.password = password
	//m.ipDomainName = ipDomainName
	//m.port = port
	//m.databaseName = databaseName

	m.reConstructMysqlConnection()

	m.secConfigChannel = make(chan int)
	m.registerSecConfigListener()
	m.loadMysqlConfig()

	go m.databaseEventLoop()

	m.configRestControlInterface()

	return true
}
