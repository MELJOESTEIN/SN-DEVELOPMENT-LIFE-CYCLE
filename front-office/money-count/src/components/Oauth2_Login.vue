<template>
    <div>
        <GoogleSignInButton
            class="btn w-100 d-flex justify-content-center align-items-center mt-3"
            @success="onSuccess"
            @error="onError"
        ></GoogleSignInButton>

    </div>
</template>

<script>
import VueJwtDecode from 'vue-jwt-decode';
import axios from 'axios';
import Cookies from 'js-cookie'
export default {
  components: { },
  data() {
    return {
      showEmail: true,
      response:'',
      users_info: '',
    }
  },
  methods: {
    async onSuccess(googleUser) {   
      const decodedCredential = VueJwtDecode.decode(googleUser.credential)
      console.log(decodedCredential)
      console.log(decodedCredential.kid)
      await axios({
        method: "post",
        url: 'http://localhost:4000/login',
        data: {
          email: decodedCredential.email,
          password: decodedCredential.kid,
        },
    }).then(response => {
        this.$swal.fire({
          position: 'top-end',
          icon: 'success',
          title: 'Good Login',
          showConfirmButton: false,
          timer: 1500
        }),
        this.$router.push("/home")
        this.users_info = response.data.data.token
        localStorage.setItem('hom', 'refresh')
        Cookies.set('session', this.users_info , { expires: 1, httpOnly: true });
        Cookies.set('session', this.users_info, { expires: 1, domain: document.location.hostname });
    }).catch(e => {
        this.$swal('Login', 'Please verify your credentials','error')
        this.$router.push({name:"Login"})
        
    })
  },
    onError(error) {
      this.$swal('Login', 'Please verify your credentials','error')
      this.$router.push({name:"Login"})
    },

  },
  mounted() {
   
  }

}
</script>


<!-- https://console.cloud.google.com/apis/credentials?project=epicoin-373101&supportedpurview=project -->

<style>

</style>