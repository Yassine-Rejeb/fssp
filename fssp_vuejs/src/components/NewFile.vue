
<script setup>
import axios from 'axios';
import { reactive, ref } from 'vue';
import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

let fileName = ref('');

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
  }
}

async function createFile() {
  try {
    let csrf = await getCsrfToken();
    await axios.post(DJANGO_API_URL + 'add_file', 
    {
      file_name: form.file_name,
      file: form.file_content[0],
    },
    {
      withCredentials: true,
      headers: {
        'X-csrftoken': csrf, 'Content-Type': 'multipart/form-data',
      },
    } ).then((response) => {
      console.log("WTF",response);
      if (response.data.message === 'File added successfully') {
        console.log('File created successfully');
        alertContent.value = 'File added successfully';
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
  file_name: '',
  file_content: '',
});

let rules = {
  required: (value) => !!value || 'Required.',
  FileNameSize: (value) => {
    return value.length <= 50 || 'File name must be less than 50 characters.';
    },
};

</script>

<template>
  <v-card style="width: 700px;"
        class="ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto" >
    <v-card-title>Create New File</v-card-title>
    <v-card-text>
      <v-form @submit.prevent="createFile">
        <v-text-field v-model="form.file_name" label="Filename" :rules="[rules.required, rules.filename, rules.filename_size]" ></v-text-field>
        <v-file-input v-model="form.file_content" label="File" multiple :rules="[rules.required]"></v-file-input>
        <v-btn type="submit" color="primary">Create File</v-btn>
      </v-form>
    </v-card-text>
    <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
  </v-card>
</template>
