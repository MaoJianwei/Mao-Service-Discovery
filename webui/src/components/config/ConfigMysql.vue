<template>
  <div style="margin: 20px" />
  <el-form :model="form" label-width="120px" label-position="top" style="max-width: 600px">
    <el-form-item label="MySQL Server address">
      <el-input v-model="form.mysqlServerAddr" placeholder="e.g. mysql.mao.com"/>
    </el-form-item>
    <el-form-item label="MySQL Server port">
      <el-input v-model="form.mysqlServerPort" placeholder="e.g. 3306"/>
    </el-form-item>
    <el-form-item label="MySQL database name">
      <el-input v-model="form.databaseName" placeholder="e.g. MaoDB"/>
    </el-form-item>
    <el-form-item label="Username">
      <el-input v-model="form.username"/>
    </el-form-item>
    <el-form-item label="Password">
      <el-input v-model="form.password" placeholder="*** ***"/>
    </el-form-item>
    <el-form-item>
      <el-button type="primary" @click="onSubmit">Submit</el-button>
    </el-form-item>
  </el-form>
</template>

<script>

import { reactive } from 'vue'
import {ElMessage} from "element-plus";
export default {
  name: "ConfigMysql",

  data() {
    return {
      form: reactive({
        mysqlServerAddr: "",
        mysqlServerPort: "",
        databaseName: "",
        username: "",
        password: "",
      })
    }
  },

  mounted() {
    this.onLoad()
  },

  methods: {

    onLoad() {
      var vueThis = this;
      this.$http.get("/api/getMysqlInfo")
          .then(function (res) {
            var data = res.data;
            vueThis.form.mysqlServerAddr = data["mysqlServerAddr"]
            vueThis.form.mysqlServerPort = data["mysqlServerPort"] !== 0 ? data["mysqlServerPort"] : ""
            vueThis.form.databaseName = data["databaseName"]
            vueThis.form.username = data["username"]
            vueThis.form.password = ""
          })
          .catch(function (err) {
            console.log("errMao: " + err);
          });
    },

    onSubmit() {
      var vueThis = this;
      this.$http.post("/api/addMysqlInfo", this.form,
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded;'
            }
          })
          .then(function () { // res
            // setTimeout(vueThis.onLoad, 500)
            ElMessage({
              message: '数据库配置提交成功',
              type: 'success',
            })
            vueThis.onLoad()
          })
          .catch(function (err) {
            ElMessage({
              message: "数据库配置提交失败：" + err,
              type: 'warning',
            })
            console.log("errMao: " + err);
          });
    },
  },
}
</script>