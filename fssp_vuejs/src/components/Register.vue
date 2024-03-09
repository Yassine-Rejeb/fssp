<script setup>
let DJANGO_API_URL = "http://127.0.0.1:8000/api/";
import { ref , computed } from "vue";
import { useTheme } from "vuetify";
import axios from "axios";
import store from "../store";

// Data for V-Alert display
let showAlert = ref(false);
let alertContent = ref("");


const form = ref({
  username: "",
  fullname: "",
  email: "",
  password: "",
  confirm: "",
});

// Send the form data to the server
function sendRegisterData() {
  // Create a new FormData object from the form data
  let data = new FormData();
  data.append("username", form.value.username);
  data.append("fullname", form.value.fullname);
  data.append("email", form.value.email);
  data.append("password", form.value.password);

  axios
    .post(DJANGO_API_URL + "register", data)
    .then((response) => {
      console.log(response);
      if (response.data.message === "user account created successfully") {
        window.location.href = "/login";
      }else if (response.data.message === "username already taken") {
        // Change the showAlert and alertContent values to display an alert
        showAlert.value = true;
        alertContent.value = "Username already taken";

        }else if (response.data.message === "email already taken") {
        // Change the showAlert and alertContent values to display an alert
        showAlert.value = true;
        alertContent.value = "Email already taken";
        }
      })
    .catch((error) => {
      console.log(error);
    });
}

const isLoading = ref(false);

function submit() {
  if (form.value.email === "" || form.value.username === "" || form.value.fullname === "" || form.value.password === "" || form.value.confirm === "") {
    return;
  }

  if (form.value.password !== form.value.confirm) {
    alert("Passwords do not match.");
    return;
  }

  isLoading.value = true;
  setTimeout(() => {
    sendRegisterData();
    isLoading.value = false;
}, 3000);
}

// Rules definition for validating form fields
const rules = {
  required: (value) => !!value || "Required.",
  email: (value) => {
    const pattern =
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return pattern.test(value) || "Invalid e-mail.";
  },
  password: (value) => {
  const rules = {
    required: (value) => !!value || "Required.",
    email: (value) => {
      const pattern =
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
      return pattern.test(value) || "Invalid e-mail.";
    },
    password: (value) => {
      const pattern =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      return pattern.test(value) || "Invalid password. It must contain at least 8 characters, including uppercase letters, lowercase letters, digits, and symbols.";
    },
  };
  }
};

// Theme things
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
        <v-card style="width: 700px;"  class="pa-4">
          <v-card-title class="text-center">Create Your Account</v-card-title>
          <v-card-item>
            <v-form @submit.prevent="submit">
              <v-text-field
                prepend-inner-icon="mdi-account"
                :rules="[rules.required]"
                v-model="form.username"
                label="Username"
              ></v-text-field>
              <v-text-field
                prepend-inner-icon="mdi-account"
                :rules="[rules.required]"
                v-model="form.fullname"
                label="Full Name"
              ></v-text-field>
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

              <v-text-field
                type="password"
                :rules="[rules.required]"
                prepend-inner-icon="mdi-key"
                v-model="form.confirm"
                label="Confirm Password"
              ></v-text-field>

              <v-btn
                color="primary"
                variant="elevated"
                type="submit"
                block
                class="mt-2"
              >
                Register
              </v-btn>
            </v-form>
          </v-card-item>

          <v-card-action>
            <div class="mx-4">
              <v-btn block to="/login"> Login </v-btn>
            </div>
          </v-card-action>
          <v-alert class="mt-3" v-if="showAlert" type="error" closable @input="showAlert = false">{{ alertContent }}</v-alert>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>
