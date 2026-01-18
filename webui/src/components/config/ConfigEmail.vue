<template>
  <div style="margin: 20px" />
  <el-form :model="form" label-width="120px" label-position="top" style="max-width: 600px">
    <el-form-item label="Username">
      <el-input v-model="form.username"/>
    </el-form-item>
    <el-form-item label="Password">
      <el-input v-model="form.password" placeholder="*** ***"/>
    </el-form-item>
    <el-form-item label="SMTP Server address and port">
      <el-input v-model="form.smtpServerAddrPort" placeholder="e.g. smtp.mao.com:25"/>
    </el-form-item>
    <el-form-item label="Sender Email">
      <el-input v-model="form.sender"/>
    </el-form-item>
    <el-form-item label="Receiver Emails">
      <el-input v-model="form.receiver" placeholder="one line, one receiver" type="textarea" rows="10"/>
    </el-form-item>
    <el-form-item>
      <el-button type="primary" @click="onSubmit">Create</el-button>
    </el-form-item>
  </el-form>
</template>

<script>

import { reactive } from 'vue'
import {ElMessage} from "element-plus";
export default {
  name: "ConfigEmail",

  data() {
    return {
      form: reactive({
        username: "",
        password: "",
        smtpServerAddrPort: "",
        sender: "",
        receiver: "",
      })
    }
  },

  mounted() {
    this.onLoad()
  },

  methods: {

    onLoad() {
      var vueThis = this;
      this.$http.get("/api/getEmailInfo")
          .then(function (res) {
            var data = res.data;
            vueThis.form.username = data["username"]
            vueThis.form.smtpServerAddrPort = data["smtpServerAddrPort"]
            vueThis.form.sender = data["sender"]
            vueThis.form.receiver = data["receiver"].join("\n")
            vueThis.form.password = ""
          })
          .catch(function (err) {
            console.log("errMao: " + err);
          });
    },

    onSubmit() {
      var vueThis = this;
      this.$http.post("/api/addEmailInfo", this.form,
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded;'
            }
          })
          .then(function () { // res
            // setTimeout(vueThis.onLoad, 500)
            ElMessage({
              message: '邮件配置提交成功',
              type: 'success',
            })
            vueThis.onLoad()
          })
          .catch(function (err) {
            ElMessage({
              message: "邮件配置提交失败：" + err,
              type: 'warning',
            })
            console.log("errMao: " + err);
          });
    },
  },
}
</script>