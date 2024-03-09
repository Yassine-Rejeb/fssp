import { createApp } from 'vue'
import App from './App.vue'
import router from "@/router/"
import store from '@/store'
import Vuetify from './plugins/vuetify'
import { loadFonts } from './plugins/webfontloader'

loadFonts()

const app = createApp(App);
app.use(router);
app.use(Vuetify);
app.use(store);
app.mount('#app');