
<script setup>
import axios from 'axios';
import { reactive, ref } from 'vue';
import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

let showAlert = ref(false);
let alertContent = ref('');
let alertType = ref('info');

async function getCsrfToken() {
  try {
    console.log(form);
    const response = await axios.get(DJANGO_API_URL + 'get_csrf_token', { withCredentials: true });
    return response.data.csrftoken;
  } catch (error) {
    console.error('Error fetching CSRF token:', error);
    // throw error;
  }
}

async function createSecret() {
  try {
    // Check if the form is empty
    if (form.secret_name === '' || form.secret_content === '') {
      alertContent.value = 'Secret name and content cannot be empty.';
      alertType.value = 'error';
      showAlert.value = true;
      return;
    }
    const response = await axios.post(DJANGO_API_URL + 'add_secret', 
    {
      secret_name: form.secret_name,
      secret_content: form.secret_content,
    },
    {
      withCredentials: true,
      headers: {
        'X-CSRFToken': await getCsrfToken(),
      },
    } ).then((response) => {
      console.log(response);
      if (response.data.message === 'Secret created successfully') {
        console.log('Secret created successfully');
        alertContent.value = 'Secret created successfully';
        alertType.value = 'success';
        showAlert.value = true;
      } else {
        console.log(response.data.message);
        alertContent.value = response.data.message;
        alertType.value = 'error';
        showAlert.value = true;
      }
    });
  } catch (error) {
    console.error(error);
    // throw error;
  }
}

let form = reactive({
  secret_name: '',
  secret_content: '',
});

let rules = {
  required: (value) => !!value || 'Required.',
  secretNameSize: (value) => {
    return value.length <= 50 || 'Secret name must be less than 50 characters.';
    },
  secretContentSize: (value) => {
    return value.length <= 4096 || 'Secret content must be strictly less than 4097 characters.';
    },
};

</script>

<template>
  <v-card style="width: 700px;" 
        class="ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto" >
    <v-card-title>Create New Secret</v-card-title>
    <v-card-text>
      <v-form @submit.prevent="createSecret">
        <v-text-field 
          v-model="form.secret_name"
          label="Secret Name" 
          :rules="[rules.required, rules.secretNameSize]"
          >
        </v-text-field>
        <v-textarea 
          v-model="form.secret_content" 
          label="Secret Content" 
          :rules="[rules.required, rules.secretContentSize]"
          >
        </v-textarea>
        <v-btn type="submit" color="primary">Create Secret</v-btn>
      </v-form>
    </v-card-text>
    <v-card-action>
      <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
    </v-card-action>
  </v-card>
</template>
