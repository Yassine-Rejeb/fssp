import { createStore } from 'vuex';

export default createStore({
  state: {
    authenticated: true,
    theme: "light",
  },
  mutations: {
    setAuthenticated(state, value) {
      state.authenticated = value;
    },
    setTheme(state, value) {
      state.theme = value;
    },

  },
  getters: {
    authenticated: state => state.authenticated,
    theme: state => state.theme,
  },
});
