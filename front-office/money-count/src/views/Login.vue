<template>
  <div class="container-fluid">
  <div class="container-fluid d-flex flex-column justify-content-center align-items-center shadow  bg-body rounded" style="width: 500px; height: 600px; margin-top:10vh; ">
    <img class="pe-auto" src="../assets/logo.png" style="width:100px;" @click="redirect"/>
    <h2 class="mt-5">Login</h2>
  <form class="my-2">
    <div class="form-group" v-if="showEmail" >
      <label for="email">Email :</label>
      <input class="form-control w-100" type="email" id="email" v-model="email">
      <br>
      <button class="btn btn-primary w-100" type="button" @click="showEmail = false">Suivant</button>
      <Oauth2_LoginVue class="w-100"/>
      <div class="d-flex align-items-center justify-content-center my-3" style="font-size:10px;"><a href="/registry" class="underline underline-offset-2">create an account</a></div>
    </div>
    <div class="form-group" v-if="!showEmail">
      <label for="password">Mot de passe :</label>
      <input class="form-control w" type="password" id="password" v-model="password">
      <br>
      <button class="btn btn-primary w" type="submit"  @click.prevent="submit(email,password)">Se connecter</button>
      <div class="d-flex align-items-center justify-content-center my-3" style="font-size:10px;"><a href="#"> Forget Password </a></div> 
    </div>
  </form>
  </div>
  </div>
</template>

<script>
import VueJwtDecode from 'vue-jwt-decode';
import Oauth2_LoginVue from '../components/Oauth2_Login.vue';
import axios from 'axios';
import VueAxios from 'vue-axios';
import Cookies from 'js-cookie';
import logo from '../assets/logo.png';
export default {

  components: {Oauth2_LoginVue,logo},
  data() {
    return {
      email: '',
      password: '',
      showEmail: true,
      userinfo:'',
    }
  },
  methods: {
    async submit(email, password){
      await axios({
        method: "post",
        url: 'http://localhost:4000/login',
        data: {
            email: email,
            password: password,
        }
      }).then(response => {
          this.users_info = response.data.data.token
          localStorage.setItem('hom', 'refresh')
          Cookies.set('session', this.users_info , { expires: 1, httpOnly: true });
          Cookies.set('session', this.users_info, { expires: 1, domain: document.location.hostname });
          this.$swal.fire({
            position: 'top-end',
            icon: 'success',
            title: 'Good Login',
            showConfirmButton: false,
            timer: 1500
        }),
          this.$router.push({name:"Home"})
      }).catch(e => {
          this.response = e
          this.$swal('Login', 'Please verify your credentials','error')
          this.$router.push({name:"Login"})
      })
    },
    redirect(){
      localStorage.setItem('homee', 'refresh')
      this.$router.push({name:"Anonyme"})
    }
},
mounted() {}

}


</script>

<style>
* {
	margin: 0;
	padding: 0;
	box-sizing: border-box;
	font-family: 'Montserrat', "Open Sans", Helvetica, Arial, sans-serif; font-size: 12px;
}
.w{
  width: 260px !important;
}
.p-5{
  padding: 3.3em !important;
}
body {
	width: 100%;
  background-color: white;
}
.pe-auto{
  cursor:pointer;
}
</style>