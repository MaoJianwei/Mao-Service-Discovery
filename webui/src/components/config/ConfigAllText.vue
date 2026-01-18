<template>
  <div style="margin: 20px" />
  <el-input v-model="maoConfigData" type="textarea" placeholder="Loading config data ..." :autosize="{ minRows: 0, maxRows: 36 }"/>
</template>

<script>
export default {
  name: "ConfigAllText",

  data() {
    return {
      maoConfigData: "",
    }
  },

  mounted() {
    this.onLoad()
  },

  methods: {
    onLoad() {
      var vueThis = this;
      this.$http.get("/api/getAllConfigText")
          .then(function (res) {
            vueThis.maoConfigData = res.data;
          })
          .catch(function (err) {
            console.log("errMao: " + err);
          });
    },
  }
}
</script>