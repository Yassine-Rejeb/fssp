<script setup>
import axios from 'axios';
import { useRoute } from 'vue-router';
import { ref } from 'vue';

let alertContent = ref("Verifying email... Please wait.");
let alertType = ref("info");

const DJANGO_API_URL = 'http://127.0.0.1:8000/api'; // replace with your actual API URL

async function verifyEmail() {
  try {
    const router = useRoute();

    const uidb64 = router.params.uidb64;
    const token = router.params.token;

    const response = await axios.get(DJANGO_API_URL + '/verifyEmail' + '/' + uidb64 + '/' + token);
    console.log(response.data.message);
    // Assuming the backend returns a success message upon successful verification
    if (response.data.message === 'Email verified successfully') {
        console.log('Email verified successfully!');
        // Alert the user that their email has been verified
        
        alertContent.value = 'Email verified successfully!';
        alertType.value = 'success';
        
        // Wait for 3 seconds before redirecting the user to the login page
        await new Promise((resolve) => setTimeout(resolve, 3000));

        // Redirect the user to the login page
        window.location.href = '/login';
    } else {
        console.error('Email verification failed.');
        
        // Alert the user that their email verification failed
        alertContent.value = 'Email verification failed.';
        alertType.value = 'error';

        // Wait for 3 seconds before redirecting the user to the login page
        await new Promise((resolve) => setTimeout(resolve, 3000));

        // Redirect the user to the login page
        window.location.href = '/login';
        
    }
  } catch (error) {
    console.error('Error during email verification:', error);
    // Handle error scenarios, e.g., show an error message
  }
}
verifyEmail();

</script>


<template>
    <v-alert class="mt-3" :type="alertType">{{ alertContent }}</v-alert>
</template>

