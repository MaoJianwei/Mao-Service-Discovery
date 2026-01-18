<template>
    <el-row class="row-bg" justify="center">
      <el-switch
          v-model="refreshSwitch"
          size="default"
          active-text="启用刷新">
      </el-switch>
    </el-row>

    <el-table :data="maoTableData" ref="maoTable" @cell-click="maoTableClick" :cell-class-name="tableCellClassName"
              :row-class-name="tableRowClassName" empty-text="暂无数据" max-height="845px">

      <el-table-column label="" type="expand">
        <template #default="maoDetailScope">
          <el-table :data="maoDetailScope.row.attr" :border="true">
            <el-table-column label="属性" prop="attrName" width="200px"/>
            <el-table-column label="值" prop="attrValue"/>
          </el-table>
        </template>
      </el-table-column>

      <el-table-column label="Service Name" prop="serviceName" />
<!--      <el-table-column label="Device IP" prop="deviceIp" />-->
      <el-table-column label="Device IP / Report IP" prop="Report_IP" />
      <el-table-column label="Alive" prop="alive" />
      <el-table-column label="Detect Count" prop="Detect_Count" />
      <el-table-column label="Report Count" prop="Report_Count" />
      <el-table-column label="RTT Duration" prop="RTT_Duration" />
      <el-table-column label="Last Seen" prop="Last_Seen" />
      <el-table-column label="Timestamp" prop="RttOutbound_or_Remote_Timestamp" />
    </el-table>
</template>

<style>
.mao-table-expand {
  font-size: 0;
}

.mao-table-expand label {
  width: 90px;
  color: #99a9bf;
}

.mao-table-expand .el-form-item {
  margin-right: 0;
  margin-bottom: 0;
  width: 100%;
}

.el-table .warning-row {
  --el-table-tr-bg-color: var(--el-color-error-light-8);
}
.el-table .success-row {
  --el-table-tr-bg-color: var(--el-color-success-light-9);
}

.el-table .cell {
  /* Mao: support new line by \n */
  white-space: pre-line !important;
}

</style>


<script setup>
import {
  // Check,
  // Delete,
  // Edit,
  // Message,
  // Search,
  // Star,
} from '@element-plus/icons-vue'
</script>

<script>
export default {
  name: "DeviceInfo",

  data() {
    return {
      refreshSwitch: true,
      refreshTimer: '',

      maoTableData: [],
    }
  },

  mounted() {
    this.refreshData();
    this.refreshTimer = setInterval(this.refreshData, 1000);
  },

  beforeUnmount() {
    clearInterval(this.refreshTimer);
  },

  methods: {

    tableRowClassName(rowObj) {
      if (rowObj.row.alive === false) {
        return 'warning-row'
      } else {
        return ''
      }
    },


    tableCellClassName({row, column, rowIndex, columnIndex}) {
      //利用单元格的 className 的回调方法，给行列索引赋值
      row.index = rowIndex;
      column.index = columnIndex;
    },
    maoTableClick(row, column) {
      if (1 === column.index) {
        this.$refs.maoTable.toggleRowExpansion(row)
      }
    },

    refreshData() {
      if (this.refreshSwitch) {
        var vueThis = this;
        this.$http.get("/api/showMergeServiceIP")
            .then(function (res) {
              vueThis.maoTableData = [];
              var data = res.data;
              for (var i = 0; i < data.length; i++) {
                var attrs = [];
                for (let k in data[i]) {
                  attrs.push({
                      "attrName": k,
                      "attrValue": data[i][k],
                  });
                }
                attrs = attrs.sort((a, b) => {
                  return a["attrName"] < b["attrName"] ? -1 : 1;
                })

                vueThis.maoTableData.push(
                    {
                      attr: attrs,
                      serviceName: data[i]["ServiceName"] != null ? data[i]["ServiceName"] : (data[i]["Hostname"] != null ? data[i]["Hostname"] : "/"),
                      // deviceIp: data[i]["Address"] != null ? data[i]["Address"] : data[i]["Hostname"],
                      Report_IP: data[i]["Ips"] != null ? data[i]["Ips"].join("\n") : (data[i]["Address"] != null ? data[i]["Address"] : data[i]["Hostname"]),
                      alive: data[i]["Alive"],
                      Detect_Count: data[i]["DetectCount"] != null ? data[i]["DetectCount"] : "/",
                      Report_Count: data[i]["ReportCount"] != null ? data[i]["ReportCount"] : data[i]["ReportTimes"],
                      RTT_Duration: data[i]["RttDuration"] != null ? (data[i]["RttDuration"] / 1000 / 1000).toFixed(3) + "ms" : "/",
                      Last_Seen: data[i]["LastSeen"] != null ? data[i]["LastSeen"] : data[i]['LocalLastSeen'],
                      RttOutbound_or_Remote_Timestamp: data[i]["RttOutboundTimestamp"] != null ? data[i]["RttOutboundTimestamp"] : data[i]["ServerDateTime"],
                      Other_Data: data[i]["OtherData"] != null ? data[i]["OtherData"] : "/",
                    }
                );
              }
            })
            .catch(function (err) {
              console.log("errMao" + err);
            })
      }
    },


    maoDoClick() {
      console.log("DeviceControl clicked")
    },

    maoDeviceOnline(device_id) {
      var vueThis = this;
      console.log(device_id)
      this.$http.post("/api/devices/setDeviceOnline",
          {
            deviceid: device_id,
          }
      ).then(function (resp) {
        console.log(resp);
        if (resp["data"]) {
          vueThis.$notify({
            title: '成功',
            message: '这是一条成功的提示消息, maoDeviceOnline',
            type: 'success'
          });
        } else {
          vueThis.$notify.error({
            title: '错误',
            message: '这是一条错误的提示消息, maoDeviceOnline',
          });
        }
      }).catch(function (err) {
        console.log(err);
      });
    },

    maoDeviceOffline(device_id) {
      var vueThis = this;
      this.$http.post("/api/devices/setDeviceOffline",
          {
            deviceid: device_id,
          }
      ).then(function (resp) {
        console.log(resp);
        if (resp["data"]) {
          vueThis.$notify({
            title: '成功',
            message: '这是一条成功的提示消息, maoDeviceOffline',
            type: 'success'
          });
        } else {
          vueThis.$notify.error({
            title: '错误',
            message: '这是一条错误的提示消息, maoDeviceOffline'
          });
        }
      }).catch(function (err) {
        console.log(err);
      });
    },
  }
}
</script>