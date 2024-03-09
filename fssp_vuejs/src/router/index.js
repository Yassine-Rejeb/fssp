import { createRouter, createWebHistory } from 'vue-router';
import axios from 'axios';

const DJANGO_API_URL = "http://127.0.0.1:8000/api/";

import Login from '../components/Login.vue';
import Register from '../components/Register.vue';
import Files from '../components/Files.vue';
import SharedFiles from '../components/SharedFiles.vue';
import Secrets from '../components/Secrets.vue';
import SharedSecrets from '../components/SharedSecrets.vue';
import FileActivities from '../components/FileActivities.vue';
import SecretActivities from '../components/SecretActivities.vue';
import Notifications from '../components/Notifications.vue';
import Logout from '../components/Logout.vue';
import NewFile from '../components/NewFile.vue';
import NewSecret from '../components/NewSecret.vue';
import VerifyEmail from '../components/VerifyEmail.vue';
import ChangeUnverifiedEmail from '../components/ChangeUnverifiedEmail.vue';
import store from '@/store'
//import Account from '../components/Account.vue';

const routes = [
  { path: '/register', component: Register, meta: { requiresGuest: true }, props: (route) => ({ isAuthenticated: checkIfAuthenticated() }) },
  { path: '/login', component: Login, meta: { requiresGuest: true }, props: (route) => ({ isAuthenticated: checkIfAuthenticated() }) },
  { path: '/change_unverified_email', name: 'change-unverified-email', component: ChangeUnverifiedEmail, meta: { requiresGuest: true }, },
  { path: '/notifications', component: Notifications , meta: { requiresAuth: true }, props: (route) => ({ isAuthenticated: checkIfAuthenticated() }) },
  { path: '/logout', component: Logout, meta: { requiresAuth: true }, },
  //  { path: '/account', component: Account},
  { path: '/files/new', component: NewFile , meta: { requiresAuth: true }, }, 
  { path: '/files/personal', component: Files , meta: { requiresAuth: true }, },
  { path: '/files/shared', component: SharedFiles , meta: { requiresAuth: true }, },
  { path: '/files/activity', component: FileActivities , meta: { requiresAuth: true }, },
  { path: '/secrets/new', component: NewSecret , meta: { requiresAuth: true }, },
  { path: '/secrets/personal', component: Secrets , meta: { requiresAuth: true }, },
  { path: '/secrets/shared', component: SharedSecrets , meta: { requiresAuth: true }, },
  { path: '/secrets/activity', component: SecretActivities , meta: { requiresAuth: true }, },
  { path: '/', redirect: '/notifications', meta: { requiresAuth: true }, },
  { path: '/verify-email/:uidb64/:token', name: 'verify-email', component: VerifyEmail, meta: { requiresGuest: true }, },
];

const router = createRouter({
    history: createWebHistory(process.env.BASE_URL),
    routes
  });

async function checkIfAuthenticated() {
  try {
      const response = await axios.get(DJANGO_API_URL + "check_session", {withCredentials: true});
      store.state.authenticated = response.data.message === "Session exists";
      return response.data.message === "Session exists";
  }
  catch (error) {
      console.log(error);
      return false;
  }
}

router.beforeEach(async (to, from, next) => {
  const isAuthenticated = await checkIfAuthenticated();
  console.log("User isAuthenticated:", isAuthenticated);
  if (to.meta.requiresAuth && !isAuthenticated) {
    // Redirect to login if trying to access an authenticated route without login
    next('/login');
  } else if (to.meta.requiresGuest && isAuthenticated) {
    // Redirect to home if trying to access a guest-only route while authenticated
    next('/');
  } else {
    next(); // Continue navigation
  }
});

export default router;