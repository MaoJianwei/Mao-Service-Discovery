# Mao Service Discovery
|Category|Job|
|---|---|
|Build|[![Go (Linux/Win/MacOS)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/go_all.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/go_all.yml) [![Go Static (Linux/Win/MacOS)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/go_all_static.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/go_all_static.yml) [![vue3 Node.js](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/vue3-nodejs.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/vue3-nodejs.yml)|
|Test|[![CodeQL](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/codeql-analysis.yml) [![Docker Image CI](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/docker-image.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/docker-image.yml) |
|Analyze|[![Analyze Dependency Relationships Map](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/analyze_dependency_map.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/analyze_dependency_map.yml)|
|Binary Release|[![Node.js Package Publish (Commit) (Linux)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/npm-publish-linux.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/npm-publish-linux.yml) [![Node.js Package Publish (Commit) (Raspberry-Pi-arm)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/npm-publish-linux-pi-2b.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/npm-publish-linux-pi-2b.yml) [![Node.js Package Publish (Commit) (Windows)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/npm-publish-windows.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/npm-publish-windows.yml) [![Node.js Package Publish (Commit) (WebUI)](https://github.com/MaoJianwei/Mao-Service-Discovery/actions/workflows/npm-publish-webui.yml/badge.svg)](https://github.com/MaoJianwei/Mao-Service-Discovery/actions/workflows/npm-publish-webui.yml) [![Docker Image Publish](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/MaoJianwei/Mao_Service_Discovery/actions/workflows/docker-publish.yml)|
|Linux Package|[Github Docker Image](https://github.com/MaoJianwei/Mao_Service_Discovery/pkgs/container/mao_service_discovery) = [NPM official](https://www.npmjs.com/package/mao-service-discovery?activeTab=versions) = [Taobao & Alibaba Cloud mirror](https://npmmirror.com/package/mao-service-discovery/versions?tags=all&versions=all)|
|Windows Package|[NPM official](https://www.npmjs.com/package/mao-service-discovery-windows?activeTab=versions) = [Taobao & Alibaba Cloud mirror](https://npmmirror.com/package/mao-service-discovery-windows/versions?versions=all&tags=all)|
|WebUI Package|[NPM official](https://www.npmjs.com/package/mao-service-discovery-webui?activeTab=versions) = [Taobao & Alibaba Cloud mirror](https://npmmirror.com/package/mao-service-discovery-webui/versions?versions=all&tags=all)|

## Quick Show - Digital Map

![Digital Map](https://raw.githubusercontent.com/MaoJianwei/Mao_Service_Discovery/refs/heads/master/digital_map_example.png)

For this example, we utilizes the map UI and API provided by [ONOS_TopologyShow_ChineseMap](https://github.com/MaoJianwei/ONOS_TopologyShow_ChineseMap) project :)

## Build

**Method 1: Compile and link statically, and build WebUI 2.0**
```
./build_all.sh
```

Method 2: Compile and link statically
```
./statically_linked_compilation.sh
```

Method 3: Build WebUI 2.0
```
./build_webui.sh
```

## Run

**Example 1: Run client**
```
./MaoServerDiscovery client --report_server_addr 2001:db8::1 --silent --log_level WARN
```

**Example 2: Run server**

In order to open the ICMP listening socket, you need **CAP_NET_RAW capability from setcap / root account / sudo** to run this command.
```
$ sudo setcap CAP_NET_RAW+eip ./MaoServerDiscovery
$ getcap ./MaoServerDiscovery
  [output] ./MaoServerDiscovery cap_net_raw=eip
```
```
./MaoServerDiscovery server --report_server_addr :: --silent --log_level WARN \
    --influxdb_url https://xxxxxx.maojianwei.com:12345 --influxdb_org_bucket xxxxxx --influxdb_token xxxxxx==
```

![client_help_example.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/client_help_example.png)

![server_help_example.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/server_help_example.png)

## Web UI 2.0

![WebUI_1.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/WebUI_1.png)

![WebUI_1_1.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/WebUI_1_1.png)

![WebUI_2.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/WebUI_2.png)

![WebUI_3.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/WebUI_3.png)


## Software Architecture
Please refer to [MODULES.md](https://github.com/MaoJianwei/Mao_Service_Discovery/blob/master/MODULES.md) file.

## Todo List
Please refer to the [agile board](https://github.com/users/MaoJianwei/projects/3).

## Initial need
Discover your service by two methods:

1. Client-Server mode, using gRPC stream.
2. Server-only mode, using ICMP.
3. Using etcd.

### Product: Client-Server mode, using gRPC stream.
#### 1. REST API (JSON format)
![2-json-format.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/2-json-format.png)

#### 2. Web Monitor
![2-readable-format.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/2-readable-format.png)

#### 3. CLI Output
![2-cli-output.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/2-cli-output.png)

#### 4. CLI Parameters
![2-cli-parameters.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/2-cli-parameters.png)

### Demo 1: Client-Server mode, using gRPC stream.
![Client-Server mode, using gRPC stream. 1](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/client-server-mode-1.png)

![Client-Server mode, using gRPC stream. 2](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/client-server-mode-2.png)

![client-server-mode-production.png](https://raw.githubusercontent.com/MaoJianwei/MaoServiceDiscovery/master/screenshot/client-server-mode-production.png)

### Demo 2: Using etcd.
![Using etcd.](https://raw.githubusercontent.com/MaoJianwei/Mao_Service_Discovery/master/screenshot/show_using_etcd.png)

## Architect

Jianwei Mao

https://www.MaoJianwei.com/

E-mail: maojianwei2012@126.com

.

![JetBrains Logo](https://account.jetbrains.com/static/favicon.ico) Supported by [JetBrains IDEA Open Source License](https://www.jetbrains.com/?from=Mao_Service_Framework) 2020-2024. 
