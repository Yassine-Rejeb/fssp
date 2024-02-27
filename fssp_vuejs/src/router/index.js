import { createRouter, createWebHistory } from 'vue-router';
import Login from '../components/Login.vue';
import Register from '../components/Register.vue';
import Files from '../components/Files.vue';
import SharedFiles from '../components/SharedFiles.vue';
import Secrets from '../components/Secrets.vue';
import SharedSecrets from '../components/SharedSecrets.vue';
import FileActivities from '../components/FileActivities.vue';
import SecretActivities from '../components/SecretActivities.vue';
import Notifications from '../components/Notifications.vue';
//import Account from '../components/Account.vue';

const routes = [
  { path: '/login', component: Login },
  { path: '/register', component: Register },
  { path: '/notifications', component: Notifications},
  //  { path: '/account', component: Account},
  { path: '/files/personal', component: Files},
  { path: '/files/shared', component: SharedFiles},
  { path: '/files/activity', component: FileActivities},
  { path: '/secrets/personal', component: Secrets},
  { path: '/secrets/shared', component: SharedSecrets},
  { path: '/secrets/activity', component: SecretActivities},
  { path: '/', redirect: '/notifications' }
];

const router = createRouter({
    history: createWebHistory(process.env.BASE_URL),
    routes
  });
  
  export default router;
  