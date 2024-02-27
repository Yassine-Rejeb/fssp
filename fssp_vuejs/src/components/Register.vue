<script setup>
import { ref , computed } from "vue";
import { useTheme } from "vuetify";

const form = ref({
  username: "",
  fullname: "",
  email: "",
  password: "",
  confirm: "",
});

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
    isLoading.value = false;
    alert(JSON.stringify(form.value));
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

const darkTheme = ref(false);
const theme = useTheme();

function changeTheme() {
  darkTheme.value = !darkTheme.value;
  theme.global.name.value = darkTheme.value ? "dark" : "light";
}
let authenticated = false;
</script>
<template>
  <v-container v-if="!authenticated" fluid>
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
        <v-card class="pa-4">
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
              <v-btn
                color="secondary"
                variant="elevated"
                type="button"
                block
                class="mt-2"
              >
                Login with Microsoft
              </v-btn>
            </v-form>
          </v-card-item>

          <v-card-action>
            <div class="mx-4">
              <v-btn block to="/login"> Login </v-btn>
            </div>
          </v-card-action>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>
