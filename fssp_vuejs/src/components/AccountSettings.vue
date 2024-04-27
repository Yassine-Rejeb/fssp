<script>
import axios from 'axios';
import store from '../store';

let DJANGO_API_URL = store.state.DJANGO_API_URL;

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
            currentPassword: this.currentPassword,
            newPassword: this.newPassword,
            confirmPassword: this.confirmPassword,
        }, {withCredentials: true, headers: {'X-CSRFToken': await this.getCSRFToken()}
        })
        .then(response => {
            if (response.status === 403) {
                window.location.href = '/login';
            }
            if (response.data.message === 'Password changed successfully') {
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
    async changePic() {
      // Check if there is a file in the profilePic variable
      // console.log("OKAY:",this.profilePic);
      if (this.profilePic === null) {
          this.alertType = 'error';
          this.alertContent = 'Profile Picture is required';
          this.showAlert = true;
          return;
      }
      const formData = new FormData();
      formData.append('profilePic', this.profilePic[0]);
      // console.log(typeof(this.profilePic));
      let resp = axios.post(DJANGO_API_URL + 'change_profile_pic', 
      formData,
      { 
        withCredentials: true,
        headers: {'X-CSRFToken': await this.getCSRFToken(), 'Content-Type': 'multipart/form-data'}
      }).then(response => {
          console.log(response.status);
          if (response.status === 403) {
              window.location.href = '/login';
          }
          if (response.data.message === 'Profile picture changed successfully') {
              // Alert Success
              this.alertType = 'success';
              this.alertContent = 'Profile picture changed successfully';
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
    async saveSession() {
      let resp = axios.post(DJANGO_API_URL + 'edit_session_timeout', 
      {expiry: this.sessionTimer},
      {
        withCredentials: true, 
        headers: {'X-CSRFToken': await this.getCSRFToken()}
      })
      .then(response => {
          console.log(response);
          // If the response is 403 Forbidden, reroute to /login
          if (response.status === 403) {
              window.location.href = '/login';
          }
          if (response.data.message === 'Success') {
              // Alert Success
              this.alertType = 'success';
              this.alertContent = 'Session timer saved successfully';
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
                    type="file"
                    :rules="profilePicRules"
                ></v-file-input>

                <v-btn color="primary" @click="changePic">Change Picture</v-btn>
            </div>
        </v-form>

        <v-divider class="my-5"></v-divider>

        <v-form ref="form_timers" v-model="valid" lazy-validation>
            <h3 class="mb-5" >Update Timers</h3>
            <div class="slider-container" style="display: flex; flex-direction: column; align-items: center;">
                <!-- <v-slider
                    class="w-100"
                    v-model="idleTimer"
                    label="Idle Timer (minutes)"
                    min="5"
                    max="360"
                    step="5"
                    thumb-label
                ></v-slider> -->
                <v-slider
                    class="w-100"
                    v-model="sessionTimer"
                    label="Session Timer (minutes)"
                    min="15"
                    max="720"
                    step="5"
                    thumb-label
                ></v-slider>
                <v-btn color="primary" @click="saveSession">Save Session</v-btn>
            </div>
        </v-form>
      </v-card-text>
    </v-card>
    <v-alert class="mt-3" v-if="showAlert" :type="alertType" closable @input="showAlert = false" >{{alertContent}}</v-alert>
  </v-container>
</template>

