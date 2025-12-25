<template>
  <div style="margin: 20px" />
  <el-form :model="form" label-width="120px" label-position="top" style="max-width: 600px">
    <el-form-item label="Security Key">
      <el-input v-model="form.secKey" placeholder="*** ***"/>
    </el-form-item>
    <el-form-item>
      <el-button type="primary" @click="onSubmit">Submit</el-button>
    </el-form-item>
  </el-form>
</template>

<script>

import { reactive } from 'vue'
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
            vueThis.onLoad()
          })
          .catch(function (err) {
            console.log("errMao: " + err);
          });
    },
  },
}
</script>