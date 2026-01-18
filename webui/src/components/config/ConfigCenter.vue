<template>
  <div style="margin: 20px" />
  <el-form :model="form" label-width="120px" label-position="top" style="max-width: 600px">
    <el-form-item label="Security Key">
      <el-input v-model="form.secKey" show-password placeholder="*** ***"/>
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
  name: "ConfigCenter",

  data() {
    return {
      form: reactive({
        secKey: "",
      })
    }
  },

  mounted() {
    this.onLoad()
  },

  methods: {

    onLoad() {
      this.form.secKey = ""
      // var vueThis = this;
      // this.$http.get("/api/getEmailInfo")
      //     .then(function (res) {
      //       var data = res.data;
      //       vueThis.form.username = data["username"]
      //       vueThis.form.smtpServerAddrPort = data["smtpServerAddrPort"]
      //       vueThis.form.sender = data["sender"]
      //       vueThis.form.receiver = data["receiver"].join("\n")
      //       vueThis.form.password = ""
      //     })
      //     .catch(function (err) {
      //       console.log("errMao: " + err);
      //     });
    },

    onSubmit() {
      var vueThis = this;
      this.$http.post("/api/setConfigSecKey", this.form,
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded;'
            }
          })
          .then(function () { // res
            // setTimeout(vueThis.onLoad, 500)
            ElMessage({
              message: '密钥提交成功',
              type: 'success',
            })
            vueThis.onLoad()
          })
          .catch(function (err) {
            ElMessage({
              message: "密钥提交失败：" + err,
              type: 'warning',
            })
            console.log("errMao: " + err);
          });
    },
  },
}
</script>