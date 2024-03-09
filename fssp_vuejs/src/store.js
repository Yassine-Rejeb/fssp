import { createStore } from 'vuex';
import axios from 'axios'; // Assuming you're using axios for HTTP requests

export default createStore({
  state: {
    authenticated: false,
    // theme: "light",
  },
  mutations: {
    setAuthenticated(state, value) {
      state.authenticated = value;
    },
    // setTheme(state, value) {
    //   state.theme = value;
    // },
  },
  // actions: {
  //   checkAuthentication({ commit }) {
  //     setInterval(async () => {
  //       try {
  //         console.log("from within the store, the authenticated value is ", this.state.authenticated);
  //         const response = await axios.get('http://127.0.0.1:8000/api/check_session', { withCredentials: true });
  //         // console.log("from within the store, the authenticated value is ", this.state.authenticated);
  //         if (response.data && response.data.message === "Session exists") {
  //           commit('setAuthenticated', true);
  //         }else{
  //           commit('setAuthenticated', false);
  //         }
  //       } catch (error) {
  //         console.error(error);
  //       }
  //     }, 500);
  //   },
  // },
  getters: {
    authenticated: state => state.authenticated,
    // theme: state => state.theme,
  },
});