
<script setup>
import axios from 'axios';
import store from '@/store';

const DJANGO_API_URL = 'your_django_api_url'; // replace with your actual API URL

async function createSecret() {
  try {
    // Adjust the API endpoint and data structure based on your server implementation
    const response = await axios.post(DJANGO_API_URL + 'create_secret', {
      name: secretName,
      content: secretContent,
    });
    console.log('Secret created:', response.data);
    // Add further actions as needed
  } catch (error) {
    console.error(error);
    // Handle error scenarios
  }
}

let secretName = '';
let secretContent = '';

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
  <v-card style="height: 400px;width: 900px;" class="ma-7 pa-8 text-center d-block rounded-lg elevation-15 mx-auto" >
    <v-card-title>Create New Secret</v-card-title>
    <v-card-text>
      <v-form @submit.prevent="createSecret">
        <v-text-field v-model="secretName" label="Secret Name" :rules="[rules.required, rules.secretNameSize]"></v-text-field>
        <v-textarea v-model="secretContent" label="Secret Content" :rules="[rules.required, rules.secretContentSize]"></v-textarea>
        <v-btn type="submit" color="primary">Create Secret</v-btn>
      </v-form>
    </v-card-text>
  </v-card>
</template>
