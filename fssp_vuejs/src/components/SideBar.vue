<script>
//import profileImage from '@/assets/images/profile.png';
import store from '@/store';

const baseLinks = [
{ text: 'Notifications', route: '/notifications', icon: 'mdi-bell' },
{ text: 'Account Settings', route: '/account', icon: 'mdi-account' },
];

const fileLinks = [
  { text: 'New File', route: '/files/new', icon: 'mdi-file-plus' },
  { text: 'Owned Files', route: '/files/personal', icon: 'mdi-folder' },
  { text: 'Shared Files', route: '/files/shared', icon: 'mdi-share' },
  { text: 'File Activities', route: '/files/activity', icon: 'mdi-history' },
];

const secretLinks = [
  { text: 'New Secret', route: '/secrets/new', icon: 'mdi-plus' },
  { text: 'Owned Secrets', route: '/secrets/personal', icon: 'mdi-lock' },
  { text: 'Shared Secrets', route: '/secrets/shared', icon: 'mdi-share-variant' },
  { text: 'Secret Activities', route: '/secrets/activity', icon: 'mdi-history' },
];

export default {
  data() {
    return {
      drawerIsExtended: false,
      authenticated: ref(store.state.authenticated),
      baseLinks,
      fileLinks,
      secretLinks,
      //profileImage: profileImage,
    };
  },
  watch: {
    '$vuetify.application.left'() {
      this.drawerIsExtended = this.$vuetify.application.left >= 200;
      console.log("Nav Headings appear:",this.drawerIsExtended);
    },
  },
};
</script>

<script setup>
let DJANGO_API_URL = "http://127.0.0.1:8000/api/";
import { ref , computed } from "vue";
import { useTheme } from "vuetify";

const darkTheme = ref(false);
const theme = useTheme();

darkTheme.value = localStorage.getItem("Dark_Theme") === "true";
theme.global.name.value = darkTheme.value ? "dark" : "light";
// store.commit("setTheme", darkTheme.value);

function changeTheme() {
  darkTheme.value = !darkTheme.value;
  theme.global.name.value = darkTheme.value ? "dark" : "light";
  localStorage.setItem("Dark_Theme", darkTheme.value);
}

const user = ref({
  username: "test",
  fullname: "John Doe",
  email: "test",
  status2FA: false,
  criticalLockStat: false,
  idleTime: 0,
});

let profileImage = ref("");

// Get the user details from the API
import axios from "axios";
axios.get(DJANGO_API_URL + "get_user_details", {withCredentials: true,})
  .then((response) => {
    user.value = response.data;
  })
  .catch((error) => {
    console.log(error);
  });

// Get the user's profile image from the API and save it in @/assets/images/profile.png of the vuejs app filesystem
axios.get(DJANGO_API_URL + "get_profile_pic", {withCredentials: true,})
  .then((response) => {
    let arr = response.data
    profileImage.value = "data:image/png;base64,"+arr; 
    console.log(profileImage.value);
  })
  .catch((error) => {
    console.log(error);
  });


</script>

<template>
    <!--  -->
    <VNavigationDrawer 
    expand-on-hover
    rail
    permanent
    color="primary"
    @mouseenter="drawerIsExtended=true"
    @mouseleave="drawerIsExtended=false"
    class="elevation-13"
    >
    <VList>
        <VListItem
          :prepend-avatar="profileImage"
          :title="user.fullname"
          :subtitle="user.email"
        ></VListItem>
    </VList>

    <VDivider></VDivider>

    <VList density="compact" nav>
        <VListItem
            v-for="link in baseLinks"
            :key="link.text"
            :prepend-icon="link.icon"
            :title="link.text"
            :value="link.text"
            :to="link.route"
            >
        </VListItem>
    <!-- </VList> -->

    <v-divider></v-divider>

    <template v-if="drawerIsExtended" >
      <p class="sidebar-heading">File Management</p>
    </template>
    <!-- <VList density="compact" nav> -->
        <VListItem
            v-for="link in fileLinks"
            :key="link.text"
            :prepend-icon="link.icon"
            :title="link.text"
            :value="link.text"
            :to="link.route">
        </VListItem>
    <!-- </VList> -->

    <v-divider></v-divider>


    <template v-if="drawerIsExtended" >
          <p class="sidebar-heading" >Secret Management</p>
    </template>


    <!-- <VList density="compact" nav> -->
        <VListItem
            v-for="link in secretLinks"
            :key="link.text"
            :prepend-icon="link.icon"
            :title="link.text"
            :value="link.text"
            :to="link.route"
            >
        </VListItem>
    <!-- </VList> -->

    <v-divider></v-divider>

    <!-- <VList density="compact" nav > -->
        <VListItem  @click="changeTheme"
                    :prepend-icon="darkTheme ? 'mdi-weather-sunny' : 'mdi-weather-night'"
                    :title="'Switch Theme'"
                    >
        </VListItem>
    <!-- </VList> -->
    <v-divider></v-divider>

    <!-- <VList density="compact" nav> -->
        <VListItem
            key="Logout"
            prepend-icon="mdi-logout"
            title="Logout"
            value="Logout"
            to="/Logout"
        >
        </VListItem>
    </VList>
    <p>{{ authenticated.value }}</p>
    </VNavigationDrawer>
</template>

<style>
.sidebar-heading {
  font-family: Arial, sans-serif;
  font-size: 16px;
  font-weight: bold;
  color: white;
  padding: 10px;
  margin: 0;
  white-space: nowrap;
}
</style>