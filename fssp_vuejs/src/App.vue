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
    }
  }
)

</script>

<template>
  <VApp id="app">
    <!-- <p> Authenticated: {{ authenticated }}</p> -->
    <!-- Side Bar -->
    <VContent class="mx-16">
      <!-- <v-alert type="info" class="mt-5">
        You are not authenticated. Please login to access the application.
      </v-alert> -->
      <VMain>
        <RouterView />
      </VMain>
    </VContent>
    <SideBar v-if="authenticated" />
  </VApp>
</template>
