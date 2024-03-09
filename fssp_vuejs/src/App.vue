<script setup>
import axios from "axios";
import SideBar from "./components/SideBar.vue";
import { useStore } from 'vuex';
import { ref } from "vue";

// Use the store to watch for changes in the authenticated state
const store = useStore()
const authenticated = ref(false)
const showSideBar = ref(false)

store.watch(
  (state) => state.authenticated,
  (newVal) => {
    if (newVal) {
      authenticated.value = newVal
      showSideBar.value = true
      // console.log('Authenticated value changed:', newVal, 'showSideBar:', showSideBar.value, 'authenticated:', authenticated.value);
    }
  }
)
// console.log("Authenticated:", authenticated.value, "showSideBar:", showSideBar.value);

// store.dispatch("checkAuthentication");

</script>

<template>
  <VApp id="app">
    <!-- <p> Authenticated: {{ authenticated }}</p> -->
    <!-- Side Bar -->
    <VContent class="mx-16">
      <VMain>
        <RouterView />
      </VMain>
    </VContent>
    <SideBar v-if="authenticated" />
  </VApp>
</template>
