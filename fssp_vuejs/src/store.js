import { createStore } from 'vuex';


export default createStore({
  state: {
    authenticated: false,
    // Get the  Django service URL from the environment variable
    // DJANGO_API_URL: 'https://django-api.default:30800/api/',
    // DJANGO_API_URL: 'https://127.0.0.1:8000/api/',
    DJANGO_API_URL: 'https://api.m0d4s.me/api/',
    // theme: "light",
  },
  mutations: {
    setAuthenticated(state, value) {
      state.authenticated = value;
    }
    // setTheme(state, value) {
    //   state.theme = value;
    // },
  },
  getters: {
    authenticated: state => state.authenticated,
    // theme: state => state.theme,
  },
});