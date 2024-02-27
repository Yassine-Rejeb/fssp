<script setup>
import SideBar from "./components/SideBar.vue";
// import Files from "./components/Files.vue"
// import SharedFiles from './components/SharedFiles.vue'
// import Secrets  from './components/Secrets.vue'
// import SharedSecrets  from './components/SharedSecrets.vue'
import Login from './components/Login.vue'
import Register from './components/Register.vue'
import { RouterView } from "vue-router"
import Store from "./store"

let authenticated = Store.state.authenticated
let theme = "dark"
</script>

<script >
export default {
setup() {
    const route = useRoute()
    const currentUrl = route.path

    return {
      currentUrl,
    }
  },
};
// Log the current URL
</script>


<template  >
  <VApp id="app" >
    <!-- Side Bar -->

    <Login v-if="!authenticated" />
    <!-- <Register v-if="!authenticated" /> -->
    
    <SideBar v-if="authenticated" />
    <!-- Files -->
    <VContent class="ml-16" v-if="authenticated">
      <!-- <Files  /> -->
      <!-- <SharedFiles /> -->
      <!-- <Secrets /> -->
      <!-- <SharedSecrets /> -->
    
      <VMain>
      <VFadeTransition>
        <RouterView />
      </VFadeTransition>
    </VMain>
  </VContent>
  </VApp>
</template>