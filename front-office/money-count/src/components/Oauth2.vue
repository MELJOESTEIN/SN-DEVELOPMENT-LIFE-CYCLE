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
export default {
components: { },
data() {
  return {
    showEmail: true,
    response:'',
  }
},
methods: {
  async onSuccess(googleUser) {
    const decodedCredential = VueJwtDecode.decode(googleUser.credential)
    console.log(decodedCredential)
    console.log(decodedCredential.kid)
    await axios({
      method: "post",
      url: 'http://localhost:4000/register',
      data: {
        firstname: decodedCredential.family_name,
        lastname: decodedCredential.given_name,
        username: decodedCredential.name,
        email: decodedCredential.email,
        password: decodedCredential.kid,
        role:'admin',
      }
    }).then(response => {
      console.log(response)
      this.$swal('Registry', 'Good login','success', 'OK')
      this.$router.push({ name: "Login"})
    }).catch(e => {
      e.code
      this.$swal('Registry', 'Try again','error')
      router.push({name:"Registry"})
    })
  },
  onError(error) {
    this.$swal('Registry', 'Try again','error')
    router.push({name:"Registry"})
  }
}
}
</script>


<!-- https://console.cloud.google.com/apis/credentials?project=epicoin-373101&supportedpurview=project -->

<style>

</style>
