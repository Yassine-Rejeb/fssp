<script setup>
import { ref , computed } from "vue";
import { useTheme } from "vuetify";
import axios from "axios";
import store from "../store";

let showAlert = ref(false);
let alertContent = ref("");

let DJANGO_API_URL = store.state.DJANGO_API_URL;

console.log("DJANGO_API_URL:", DJANGO_API_URL);

async function getCSRFToken() {
  try {
    const response = await axios.get(DJANGO_API_URL + "gen_csrf_token", {withCredentials: true,})
    .then((response) => {
      // console.log("CSRF Token:", response.data.csrf_token);
      return response.data;
    }).catch((error) => {
      console.log(error);
    });
    return response;
  } catch (error) {
    console.error("Error fetching CSRF token:", error);
  }
}

async function sendLoginData() {
  let data = new FormData();
  data.append("email", form.value.email);
  data.append("password", form.value.password);
  axios
    .post(DJANGO_API_URL + "login", data, {withCredentials: true,})
    .then((response) => {
      console.log(response);
      if (response.data.message === "login successful" || response.data.message === "Already logged in") {
        console.log("Logged in");
        getCSRFToken().then(() => {
          window.location.href = "/notifications";
          // alert("Logged in");
        });

      } else if (response.data.message === "Credentials do not match") {
        console.log("Invalid Credentials");
        alertContent.value = "Invalid Credentials";
        showAlert.value = true;
      } else if (response.data.message === "Please verify your email before logging in. The verification email has already been sent to you. If you have made a mistake, please change your email address.") {
        // Change the showAlert, alertContent, and alertType values to display an alert
        showAlert.value = true;
        console.log("Please verify your email before logging in.");
        alertContent.value = "<p>Please verify your email before logging in.<br>If you have entered an incorrect email, <br>please follow <a href='/change_unverified_email'>THIS LINK</a> to remediate the situation.</p>";
      }
    })
    .catch((error) => {
      console.log(error);
    });
}

const form = ref({
  email: "",
  password: "",
});

const isLoading = ref(false);

function submit() {
  if (form.value.email === "") {
    return;
  }

  isLoading.value = true;
  setTimeout(() => {
    isLoading.value = false;
    sendLoginData();
  }, 3000);
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
          <v-card-title class="text-center">Welcome Back</v-card-title>
          <v-card-item>
            <v-form @submit.prevent="submit">
              <v-text-field
                prepend-inner-icon="mdi-email"
                :rules="[rules.required, rules.email]"
                v-model="form.email"
                label="Email"
              ></v-text-field>

              <v-text-field
                type="password"
                :rules="[rules.required]"
                prepend-inner-icon="mdi-key"
                v-model="form.password"
                label="Password"
              ></v-text-field>

              <router-link
                to="/ForgotPass"
                v-model="form.forgot"
                style="text-align: center; display: block; color: #1976d2;"
                class="text-decoration-none">
                  Forgot Your Password!
              </router-link>

              <v-btn
                color="primary"
                variant="elevated"
                type="submit"
                block
                class="mt-2"
              >
                Login
              </v-btn>
            </v-form>
          </v-card-item>

          <v-card-action>
            <div class="mx-4">
              <v-btn block to="/register"> Register </v-btn>
            </div>
          <v-alert class="mt-3" v-if="showAlert" type="error" closable @input="showAlert = false" v-html="alertContent" ></v-alert>
          </v-card-action>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>