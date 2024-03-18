<script>
let DJANGO_API_URL = 'http://127.0.0.1:8000/api/';
import axios from 'axios';

export default {
  data() {
    return {
        valid: true,
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
        profilePic: null,
        twoFAEnabled: false,
        idleTimer: 15,
        sessionTimer: 30,
        showAlert: false,
        alertContent: '',
        alertType: 'info',
        passwordRules: [
            v => !!v || 'Password is required',
            v => (v && v.length >= 8) || 'Password must be at least 8 characters long',
        ],
        confirmPasswordRules: [
            v => !!v || 'Confirm Password is required',
            v => v === this.newPassword || 'Passwords do not match',
        ],
        profilePicRules: [
            v => !!v || 'Profile Picture is required',
        ],
    };
  },
  methods: {
    async getCSRFToken() {
      let resp = await axios.get(DJANGO_API_URL + 'get_csrf_token', {withCredentials: true})
      .then(response => {
        return response.data.csrftoken;
      }).catch(error => {
        console.log(error);
      });
      return resp;
    },
    async ChangePass() {
        let resp = axios.post(DJANGO_API_URL + 'change_password', 
        {
            csrfToken: await this.getCSRFToken(),
            currentPassword: this.currentPassword,
            newPassword: this.newPassword,
            confirmPassword: this.confirmPassword,
        }, {withCredentials: true})
        .then(response => {
            console.log(response);
            if (response.data.message === 'Success') {
                // Alert Success
                this.alertType = 'success';
                this.alertContent = 'Password changed successfully';
                this.showAlert = true;
            }
            else {
                console.log(response.data.message);
                this.alertType = 'error';
                this.alertContent = response.data.message;
                this.showAlert = true;
            }
      }, error => {
        console.log(error);
      });
        return resp;
    },
    changePic() {
      let resp;
    },
    saveSession() {
      if (this.$refs.form_timers.validate()) {
        console.log('Session timers saved');
      }
    },
  },
};
</script>

<template>
  <v-container>
    <v-card>
      <v-card-title>Account Settings</v-card-title>
      <v-card-text>
        <v-divider class="my-5"></v-divider>
        <v-form ref="form_pass" v-model="valid" lazy-validation>
            <h3 class="mb-5" >Edit Password</h3>
            <div class="slider-container" style="display: flex; flex-direction: column; align-items: center;">
                <v-text-field
                    class="w-100"
                    v-model="currentPassword"
                    label="Current Password"
                    type="password"
                    :rules="passwordRules"
                    required
                ></v-text-field>

                <v-text-field
                    class="w-100"
                    v-model="newPassword"
                    label="New Password"
                    type="password"
                    :rules="passwordRules"
                    required
                ></v-text-field>

                <v-text-field
                    class="w-100"
                    v-model="confirmPassword"
                    label="Confirm New Password"
                    type="password"
                    :rules="confirmPasswordRules"
                    required
                ></v-text-field>

                <v-btn class="w-auto" color="primary" @click="ChangePass" style="margin-top: 10px;">Change Password</v-btn>
            </div>
        </v-form>

        <v-divider class="my-5"></v-divider>

        <v-form ref="form_pic" v-model="valid" lazy-validation>
            <h3 class="mb-5" >Update Profile Picture</h3>
            <div class="slider-container" style="display: flex; flex-direction: column; align-items: center;">
                <v-file-input
                    class="w-100"
                    v-model="profilePic"
                    label="Profile Picture"
                    accept="image/*"
                    :rules="profilePicRules"
                ></v-file-input>

                <v-btn color="primary" @click="changePic">Change Picture</v-btn>
            </div>
        </v-form>

        <v-divider class="my-5"></v-divider>

        <v-form ref="form_timers" v-model="valid" lazy-validation>
            <h3 class="mb-5" >Update Timers</h3>
            <div class="slider-container" style="display: flex; flex-direction: column; align-items: center;">
                <v-slider
                    class="w-100"
                    v-model="idleTimer"
                    label="Idle Timer (minutes)"
                    min="5"
                    max="360"
                    step="5"
                    thumb-label
                ></v-slider>
                <v-slider
                    class="w-100"
                    v-model="sessionTimer"
                    label="Session Timer (minutes)"
                    min="15"
                    max="720"
                    step="5"
                    thumb-label
                ></v-slider>
                <v-btn color="primary" @click="saveTimers">Save Timers</v-btn>
            </div>
        </v-form>
      </v-card-text>
    </v-card>
    <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
  </v-container>
</template>

