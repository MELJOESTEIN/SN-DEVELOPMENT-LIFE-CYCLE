<template>
  <main id="Profil-page container-fluid">
    <form class="card">
      <div class="card-header deconnect">
        <div class="one">
          <h4 class="card-heading">Edit Profile</h4>
        </div>
        <div class="two">
          <span class="material-icons" style="" @click="deconnect"
            >power_settings_new</span
          >
        </div>
      </div>
    </form>
    <form class="profil_content card mb-4">
      <div class="card-body">
        <div class="col-sm-6 col-md-6">
          <div class="mb-4" style="display: flex">
            <Profil_Photo />
            <p style="margin-top: 15px; margin-left: 15px">{{ this.name }}</p>
          </div>
        </div>
        <div class="row">
          <div class="col-sm-6 col-md-6">
            <div class="mb-4">
              <label class="form-label">Name</label>
              <input class="form-control" type="text" placeholder="Name" />
            </div>
          </div>

          <div class="col-sm-6 col-md-6">
            <div class="mb-4">
              <label class="form-label">Last Name</label>
              <input class="form-control" type="text" placeholder="Lastname" />
            </div>
          </div>

          <div class="col-sm-6 col-md-6">
            <div class="mb-4">
              <label class="form-label">Old Password</label>
              <input
                class="form-control"
                type="text"
                placeholder="Old Password"
              />
            </div>
          </div>

          <div class="col-sm-6 col-md-6">
            <div class="mb-4">
              <label class="form-label">New Password</label>
              <input
                class="form-control"
                type="text"
                placeholder="New Password"
                v-model="newPassword"
              />
            </div>
          </div>

          <div class="col-md-12">
            <div class="mb-4">
              <label class="form-label">Confirm Password</label>
              <input
                class="form-control"
                type="text"
                placeholder="Confirm Password"
                v-model="passwordVerify"
              />
            </div>
          </div>
        </div>
      </div>
      <div class="card-footer text-end">
        <button class="btn btn-primary" type="submit" @click.prevent="submitForm">Update Profile</button>
      </div>
    </form>
  </main>
</template>
  
  <script>
import { assert } from "@vue/compiler-core";
import Cookies from "js-cookie";
import Profil_Photo from "../components/Profil_Photo.vue";
import VueJwtDecode from "vue-jwt-decode";

export default {
  components: { Profil_Photo },
  data() {
    return {
      showEmail: true,
      response: "",
      name: "",
      newPassword: "",
      passwordVerify: "",
    };
  },
  methods: {
    deconnect() {
      Cookies.remove("session");
      this.$swal.fire({
        position: "top-end",
        icon: "success",
        title: "GOODBAY",
        showConfirmButton: false,
        timer: 1500,
      }),
        this.$router.push({ name: "Login" });
      this.$router.push("/login");
    },
    sessionRecup() {
      const session = Cookies.get("session");
      const dec = VueJwtDecode.decode(session);
      this.name = dec.username;
    },
    submitForm() {
      //check password
      if (this.newPassword !== this.passwordVerify) {        
        this.$swal.fire({
        position: "top-end",
        icon: "error",
        title: "Passwords must match",
        showConfirmButton: false,
        timer: 1500,
      })
      

      return;
      } else {
        this.$swal.fire({
        position: "top-end",
        icon: "success",
        title: "Modifications applied",
        showConfirmButton: false,
        timer: 1500,
      })
      }
    },
  },
  mounted() {
    this.sessionRecup();
  },
};
</script>


  
  <style lang="scss" scoped>
/*.avatar.avatar-lg {
  width: 10rem;
  height: 10rem;
  line-height: 5rem;
}
.avatar {
  display: inline-block;
  position: relative;
  width: 3rem;
  height: 3rem;
  text-align: center;
  border: #dee2e6;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 0.5rem 1rem rgb(0 0 0 / 15%);
  line-height: 3rem;
}*/

.logout {
  position: relative;
  display: flex;
  flex-direction: row;
  margin-left: 95%;
  color: grey;
}

.deconnect {
  position: relative;
  display: flex;
  flex-direction: row;
  justify-content: space-between;
  .two {
    color: var(--red);
    cursor: pointer;
  }
}
</style>
