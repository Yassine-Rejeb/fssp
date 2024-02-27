// Styles
import '@mdi/font/css/materialdesignicons.css'
import 'vuetify/styles'

// Vuetify
import { createVuetify } from 'vuetify'
export default createVuetify({
  themes: {
    light: {
      dark: false,
      colors: {
        background: '#ffffff',
        surface: '#f5f5f5',
        primary: '#1867c0',
        secondary: '#37474f',
        error: '#b71c1c',
        info: '#2196f3',
        success: '#4caf50',
        warning: '#fb8c00',
        object: '#f0f0f0',
      },
    },
    dark: {
      dark: true,
      colors: {
        background: '#121212',
        surface: '#212121',
        primary: '#424242',
        secondary: '#757575',
        error: '#cf6679',
        info: '#2196f3',
        success: '#4caf50',
        warning: '#fb8c00',
        object: '#333333',
      },
    },
  },
})