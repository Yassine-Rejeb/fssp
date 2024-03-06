<script setup>
import axios from "axios";
import { ref } from "vue";
import store from "../store";

const DJANGO_API_URL = "http://127.0.0.1:8000/api/";

function sendLogoutRequest() {
  axios
    .get(DJANGO_API_URL + "logout", {withCredentials: true,})
    .then((response) => {
      console.log(response);
      // store.state.authenticated = false;
      // authenticated = store.state.authenticated;
      window.location.href = "/login";
    })
    .catch((error) => {
      console.log(error);
    });
}

const isLoading = ref(false);


isLoading.value = true;
setTimeout(() => {
isLoading.value = false;
sendLogoutRequest();
}, 1000);

</script>

<template>

</template>