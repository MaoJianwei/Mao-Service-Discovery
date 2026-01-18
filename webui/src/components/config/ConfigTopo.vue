<template>
  <div style="margin: 20px" />

  <el-form :model="form" label-width="120px" label-position="top" style="max-width: 600px" action="/addServiceIp" method="post">
    <el-form-item label="ONOS Endpoint address and port">
      <el-input v-model="form.addrPort" placeholder="e.g. 127.0.0.1:8181"/>
    </el-form-item>
    <el-form-item>
      <el-button type="primary" @click="onSubmit">Create</el-button>
    </el-form-item>
  </el-form>

  <el-table :data="maoOnosTableData" ref="maoTable" :row-class-name="tableRowClassName"
            empty-text="暂无数据" max-height="610px">
    <el-table-column label="API Name" prop="API_NAME" />
    <el-table-column label="API URL" prop="API_URL" />
  </el-table>
</template>

<script>

import {reactive} from 'vue'
import {ElMessage} from "element-plus";

export default {
  name: "ConfigTopo",

  data() {
    return {
      form: reactive({
        addrPort: "",

      }),
      maoOnosTableData: [],
    }
  },

  mounted() {
    this.onLoad()
  },

  methods: {
    tableRowClassName(rowObj) {
      if (rowObj.row.API_URL.indexOf("%") !== -1) {
        return 'warning-row'
      } else {
        return ''
      }
    },

    onSubmit() {
      var vueThis = this;
      this.$http.post("/api/addOnosInfo", this.form,
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded;'
            }
          })
          .then(function () { // res
            // setTimeout(vueThis.onLoad, 500)
            ElMessage({
              message: '拓扑配置提交成功',
              type: 'success',
            })
            vueThis.onLoad()
          })
          .catch(function (err) {
            ElMessage({
              message: "拓扑配置提交失败：" + err,
              type: 'warning',
            })
            console.log("errMao: " + err);
          });
    },

    onLoad() {
      var vueThis = this;
      this.$http.get("/api/getOnosInfo")
          .then(function (res) {
            vueThis.maoOnosTableData = [];
            for (var k in res.data) {
              if (k === "addrPort") {
                vueThis.form.addrPort = res.data[k];
              } else {
                vueThis.maoOnosTableData.push(
                    {
                      API_NAME: k,
                      API_URL: res.data[k],
                    }
                );
              }
            }
          })
          .catch(function (err) {
            console.log("errMao: " + err);
          });
    },
  }
}
</script>