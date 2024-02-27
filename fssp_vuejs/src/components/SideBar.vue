<script>
import profileImage from '@/assets/images/profile.png';

import { useRoute } from 'vue-router'

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

const logout = [
  { text: 'Logout', route: '/logout', icon: 'mdi-logout' },
];



export default {
    setup() {
    const route = useRoute();
    const currentUrl = route.fullPath;
    console.log(currentUrl);

    return {
      currentUrl,
    };
  },
    data() {
        return {
            baseLinks,
            fileLinks,
            secretLinks,
            logout,
            profileImage: profileImage,
      };
    },
    theme: {
    defaultTheme: 'dark'
    }
};

</script>

<script setup>
import store from "../store";
import { ref , computed } from "vue";
import { useTheme } from "vuetify";


const darkTheme = ref(false);
const theme = useTheme();


function changeTheme() {
  darkTheme.value = !darkTheme.value;
  theme.global.name.value = darkTheme.value ? "dark" : "light";
  store.commit("setTheme", darkTheme.value);
}
</script>

<template>
    <VNavigationDrawer
    expand-on-hover
    rail
    permanent
    color="primary"
    class="elevation-13"
    >
    <VList>
        <VListItem
        :prepend-avatar="profileImage"
        title="John Doe"
        subtitle="Email"
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

    <p class="sidebar-heading">File Management</p>

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

    <p class="sidebar-heading underlined" >Secret Management</p>

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
            v-for="link in logout"
            :key="link.text"
            :prepend-icon="link.icon"
            :title="link.text"
            :value="link.text"
            :to="link.route"
            >
        </VListItem>
    </VList>

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