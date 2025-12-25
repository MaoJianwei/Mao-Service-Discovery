<template>
  <div>
    <!--    <el-tabs class="tabClass">-->
    <!--      <el-tab-pane label="邮件通知配置" name="config-email"></el-tab-pane>-->
    <!--      <el-tab-pane label="ICMP检测配置" name="config-icmp"></el-tab-pane>-->
    <!--      <el-tab-pane label="拓扑接口配置" name="config-topo"></el-tab-pane>-->
    <!--    </el-tabs>-->
    <el-menu
        default-active="/config/config"
        mode="horizontal"
        router>
      <!--        @select="handleSelect"-->

      <el-menu-item index="/config/config">配置中心</el-menu-item>
      <el-menu-item index="/config/email">邮件通知配置</el-menu-item>
      <el-menu-item index="/config/icmp">ICMP检测配置</el-menu-item>
      <el-menu-item index="/config/grpc">gRPC服务管理</el-menu-item>
      <el-menu-item index="/config/topo">拓扑接口配置</el-menu-item>
      <el-menu-item index="/config/mysql">MySQL接口配置</el-menu-item>
      <el-menu-item index="/config/allText">配置文件导出</el-menu-item>
    </el-menu>
    <router-view name="maoConfig"></router-view>
  </div>
</template>

<style>
/*.tabClass > .el-menu__content {*/
/*  padding: 32px;*/
/*  color: #6b778c;*/
/*  font-size: 32px;*/
/*  font-weight: 600;*/
/*}*/
</style>

<script>
export default {
  name: "ConfigPages",

  data() {
    return {
      // refreshSwitch: false,
      // refreshTimer: '',
      // maoTableData: [
      //   // {
      //   //   maoObj: '<div class="cell">qingdao</div>',
      //   //   maoDetail: "mao-detail"
      //   // }
      // ]
    }
  },

  mounted() {
  },

  methods: {
    // handleSelect(key, keyPath) {
    //   console.log(key)
    //   console.log(keyPath)
    //   // this.$router.push({
    //   //   path: key,
    //   //   params: {data: keyPath }
    //   // })
    // }
  }
}
</script>