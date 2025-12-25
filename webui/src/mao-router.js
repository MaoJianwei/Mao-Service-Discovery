// import Vue from "vue"
import { createRouter, createWebHashHistory } from 'vue-router'
import ConfigPages from "@/components/ConfigPages.vue"
import ConfigEmail from "@/components/config/ConfigEmail.vue";
import ConfigMysql from "@/components/config/ConfigMysql.vue";
import ConfigIcmp from "@/components/config/ConfigIcmp.vue";
import ConfigTopo from "@/components/config/ConfigTopo.vue";
import ConfigAllText from "@/components/config/ConfigAllText.vue";

import DeviceInfo from "@/components/DeviceInfo.vue";
import ONOS from "@/components/ONOS";
import ApiListOldApi from "@/components/ApiListOldApi.vue"
import ConfigGrpc from "@/components/config/ConfigGrpc.vue";
import ConfigCenter from "@/components/config/ConfigCenter.vue";

// Vue.use(VueRouter)

export default createRouter({
        history: createWebHashHistory(),
        routes: [
            {
                path: '/',
                components: {
                    maoMain: DeviceInfo,
                }
            },
            {
                path: '/config',
                components: {
                    maoMain: ConfigPages,
                },
                children: [
                    {
                        path: '',
                        components: {
                            maoConfig: ConfigCenter
                        }
                    },
                    {
                        path: 'config',
                        components: {
                            maoConfig: ConfigCenter
                        }
                    },
                    {
                        path: 'email',
                        components: {
                            maoConfig: ConfigEmail
                        }
                    },
                    {
                        path: 'icmp',
                        components: {
                            maoConfig: ConfigIcmp
                        }
                    },
                    {
                        path: 'grpc',
                        components: {
                            maoConfig: ConfigGrpc
                        }
                    },
                    {
                        path: 'topo',
                        components: {
                            maoConfig: ConfigTopo
                        }
                    },
                    {
                        path: 'mysql',
                        components: {
                            maoConfig: ConfigMysql
                        }
                    },
                    {
                        path: 'allText',
                        components: {
                            maoConfig: ConfigAllText
                        }
                    }
                ]
            },
            {
                path: '/deviceStatus',
                components: {
                    maoMain: DeviceInfo,
                }
            },
            {
                path: '/topo',
                components: {
                    maoMain: ONOS
                }
            },
            {
                path: '/apiListOldApi',
                components: {
                    maoMain: ApiListOldApi
                }
            }
        ]
    }
)