import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import GoogleSignInPlugin from "vue3-google-signin";
import * as Vue from 'vue' // in Vue 3
import axios from 'axios';
import VueAxios from 'vue-axios';
import VueSweetalert2 from 'vue-sweetalert2';
import 'sweetalert2/dist/sweetalert2.min.css';
import CryptoTable from "./components/Cryptos_Table.vue";
import VueCookies from 'vue-cookies'
// import store from "./store";
import "bootstrap/dist/css/bootstrap.css";



const app = createApp(App);

app.use(router);
// app.use(store);
app.component("cryptos-table", CryptoTable);
// app.config.globalProperties.$globalVar = 'globar'
app.use(GoogleSignInPlugin, {
  clientId:
    "507079347140-u6fk7ucpidq77nnijadbe8l98he231e6.apps.googleusercontent.com",
});
app.use(VueAxios, axios);
app.use(VueSweetalert2);
app.use(VueCookies);
app.mount("#app");
import "bootstrap/dist/js/bootstrap.js";
