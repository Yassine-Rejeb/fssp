<script setup>
let DJANGO_API_URL = "http://127.0.0.1:8000/api/";
import { ref , computed } from "vue";
import { useTheme } from "vuetify";
import axios from "axios";
import store from "../store";

let showAlert = ref(false);
let alertContent = ref("");
let alertType = ref("");

function sendLoginData() {
  let data = new FormData();
  data.append("current_email", form.value.currentEmail);
  data.append("password", form.value.password);
  data.append("new_email", form.value.newEmail);
  axios
    .post(DJANGO_API_URL + "change_unverifiable_email", data)
    .then((response) => {
      console.log(response);
      if (response.data.message === "Email updated successfully") {
        // Change the showAlert, alertContent, and alertType values to display an alert
        showAlert.value = true;
        alertContent.value = "Email updated successfully";
        alertType.value = "success";
        // Redirect the user to the login page after 3 seconds
        setTimeout(() => {
          window.location.href = "/login";
        }, 3000);
      } else if (response.data.message === "Credentials do not match" || response.data.message === "User does not exist") {
        //alert("Invalid Credentials");
        alertContent.value = "Invalid Credentials";
        showAlert.value = true;
        alertType.value = "error";
      } else if (response.data.message === "Email already taken") {
        // Change the showAlert, alertContent, and alertType values to display an alert
        showAlert.value = true;
        alertContent.value = "Email already registered";
        alertType.value = "error";
      } else if (response.data.message === "Email already verified") {
        // Change the showAlert, alertContent, and alertType values to display an alert
        showAlert.value = true;
        alertContent.value = "You have already verified your email, this action is not permitted anymore.";
        alertType.value = "error";
      }
    })
    .catch((error) => {
      console.log(error);
    });
}

const form = ref({
  currentEmail: "",
  password: "",
  newEmail: "",
});

const isLoading = ref(false);

function submit() {
  if (form.value.currentEmail === "" || form.value.password === "" || form.value.newEmail === "") {
    return;
  }

  isLoading.value = true;
  setTimeout(() => {
    isLoading.value = false;
    sendLoginData();
  }, 1500);
}

const rules = {
  required: (value) => !!value || "Required.",
  email: (value) => {
    const pattern =
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return pattern.test(value) || "Invalid e-mail.";
  },
};

const forgotPass = computed(() => {
  return; //form.forgot ? '/ForgotPass' : '/';
});

const darkTheme = ref(false);
const theme = useTheme();

darkTheme.value = localStorage.getItem("Dark_Theme") === "true";
theme.global.name.value = darkTheme.value ? "dark" : "light";

function changeTheme() {
  darkTheme.value = !darkTheme.value;
  localStorage.setItem("Dark_Theme", darkTheme.value);
  theme.global.name.value = darkTheme.value ? "dark" : "light";
}

</script>

<template>
  <v-container fluid>
    <v-btn class="float-start " icon @click="changeTheme">
        <v-icon
          :icon="darkTheme ? 'mdi-weather-night' : 'mdi-weather-sunny'"
        ></v-icon>
      </v-btn>
    <v-overlay :model-value="isLoading" class="align-center justify-center">
      <v-progress-circular
        v-if="isLoading"
        indeterminate
        color="white"
      ></v-progress-circular>
    </v-overlay>
    <v-row justify="center">
      <v-col md="4">
        <v-card style="width: 700px;" class="pa-4">
          <v-card-title class="text-center">Correct your email</v-card-title>
          <v-card-item>
            <v-form @submit.prevent="submit">
              <v-text-field
                prepend-inner-icon="mdi-email"
                :rules="[rules.required, rules.email]"
                v-model="form.currentEmail"
                label="Current Email"
              ></v-text-field>

              <v-text-field
                type="password"
                :rules="[rules.required]"
                prepend-inner-icon="mdi-key"
                v-model="form.password"
                label="Password"
              ></v-text-field>

              <v-text-field
                prepend-inner-icon="mdi-email"
                :rules="[rules.required, rules.email]"
                v-model="form.newEmail"
                label="New Email"
              ></v-text-field>

              <v-btn
                color="primary"
                variant="elevated"
                type="submit"
                block
                class="mt-2">
                Change Email
              </v-btn>
            </v-form>
          </v-card-item>

          <v-card-action>
            <div class="mx-4">
              <v-btn block to="/login"> Login </v-btn>
              <v-btn block to="/register"> Register </v-btn>
            </div>
          <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false">{{ alertContent }}</v-alert>
          </v-card-action>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>