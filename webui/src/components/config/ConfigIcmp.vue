<template>
  <div style="margin: 20px" />

  <el-form
      ref="formRef"
      :model="formData"
      :rules="formRules"

      style="max-width: 100%"
      label-width="auto"
  >
    <el-form-item>
      <el-button type="primary" @click="submitServices">Submit</el-button>
      <el-button @click="addServiceLine">Add</el-button>
    </el-form-item>

    <el-form-item
        v-for="(service, index) in formData.serviceIpName"
        :key="service.key"
        :label="'Service ' + (index+1)"
    >
      <el-form-item label="IP："  style="width: 40%" :prop="'serviceIpName.' + index + '.address'"
                    :rules="formRules['serviceIpName.address']">
        <el-input v-model="service.address" />
      </el-form-item>

      <el-form-item label="名称：" style="width: 40%">
        <el-input v-model="service.serviceName" />
      </el-form-item>

      <span style="width: 2%" />
      <el-button class="mt-2" @click.prevent="removeServiceLine(index)">Delete</el-button>
    </el-form-item>
  </el-form>

  <el-table :data="maoIcmpTableData" ref="maoTable" :cell-class-name="tableCellClassName"
            empty-text="暂无数据" max-height="610px">
    <el-table-column label="Control">
      <template #default="scope">
        <el-button size="small" type="danger" @click="handleDelete(scope.$index, scope.row)">Delete</el-button>
      </template>
    </el-table-column>
    <el-table-column label="Service Name" prop="serviceName" />
    <el-table-column label="Device IP" prop="deviceIp" />
    <el-table-column label="Alive" prop="alive" />
    <el-table-column label="Detect Count" prop="Detect_Count" />
    <el-table-column label="Report Count" prop="Report_Count" />
    <el-table-column label="RTT Duration" prop="RTT_Duration" />
    <el-table-column label="Last Seen" prop="Last_Seen" />
    <el-table-column label="Timestamp" prop="RttOutbound_or_Remote_Timestamp" />
  </el-table>

</template>

<script>
import {ElMessage} from "element-plus";

export default {
  name: "ConfigIcmp",
  data() {
    return {
      maoIcmpTableData: [],
      refreshTimer: "",

      formData: {
        serviceIpName: [
          {
            key: Date.now(),
            address: "",
            serviceName: "",
          }
        ]
      },

      formRules: {
        'serviceIpName.address': [{ required: true, message: 'IP can not be null', trigger: 'blur' }],
      },


      form: {
        ipv4v6: "",
      }
    }
  },

  mounted() {
    this.onLoad()
    this.refreshTimer = setInterval(this.onLoad, 1000);
  },
  beforeUnmount() {
    clearInterval(this.refreshTimer);
  },

  methods: {

    addServiceLine() {
      this.formData.serviceIpName.push({
        key: Date.now(),
        address: "",
        serviceName: "",
      })
    },

    removeServiceLine(index) {
      if (index >= 0) {
        this.formData.serviceIpName.splice(index, 1)
      }
      if (this.formData.serviceIpName.length === 0) {
        this.addServiceLine()
      }
    },

    submitServices() {
      this.$refs.formRef.validate((valid) => {
        if (valid) {
          console.log('表单验证通过，可提交数据！')
          console.log(this.formData)
          var vueThis = this;
          this.$http.post("/api/addServiceIp", this.formData,
              {
                headers: {
                  'Content-Type': 'application/json'
                }
              })
              .then(function () { // res
                // setTimeout(vueThis.onLoad, 500)
                ElMessage({
                  message: 'ICMP检测提交成功',
                  type: 'success',
                })
                vueThis.onLoad()
              })
              .catch(function (err) {
                ElMessage({
                  message: "ICMP检测提交失败：" + err,
                  type: 'warning',
                })
                console.log("errMao: " + err);
              });
        }
      })
    },



    tableCellClassName({row, column, rowIndex, columnIndex}) {
      //利用单元格的 className 的回调方法，给行列索引赋值
      row.index = rowIndex;
      column.index = columnIndex;
    },

    handleDelete(index, row) {
      var vueThis = this;
      this.$http.post("/api/delServiceIp", {ipv4v6: row.deviceIp},
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded;'
            }
          })
          .then(function () { // res
            // setTimeout(vueThis.onLoad, 500)
            ElMessage({
              message: 'ICMP检测删除成功',
              type: 'success',
            })
            vueThis.onLoad()
          })
          .catch(function (err) {
            ElMessage({
              message: "ICMP检测删除失败：" + err,
              type: 'warning',
            })
            console.log("errMao: " + err);
          });
    },

    onLoad() {
      var vueThis = this;
      this.$http.get("/api/showServiceIP")
          .then(function (res) {
            vueThis.maoIcmpTableData = [];

            var data = res.data;
            for (var i = 0; i < data.length; i++) {
              console.log(data[i])
              vueThis.maoIcmpTableData.push(
                  {
                    serviceName: data[i]["ServiceName"] != null ? data[i]["ServiceName"] : "/",
                    deviceIp: data[i]["Address"] != null ? data[i]["Address"] : data[i]["Hostname"],
                    alive: data[i]["Alive"],
                    Detect_Count: data[i]["DetectCount"] != null ? data[i]["DetectCount"] : "/",
                    Report_Count: data[i]["ReportCount"] != null ? data[i]["ReportCount"] : data[i]["ReportTimes"],
                    RTT_Duration: data[i]["RttDuration"] != null ? (data[i]["RttDuration"] / 1000 / 1000).toFixed(3) + "ms" : "/",
                    Last_Seen: data[i]["LastSeen"] != null ? data[i]["LastSeen"] : data[i]['LocalLastSeen'],
                    RttOutbound_or_Remote_Timestamp: data[i]["RttOutboundTimestamp"] != null ? data[i]["RttOutboundTimestamp"] : data[i]["ServerDateTime"],
                  }
              );
            }
          })
          .catch(function (err) {
            console.log("errMao: " + err);
          });
    },
  }
}
</script>