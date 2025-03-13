<template>

<div v-show="$route.name =='Anonyme'">
	<topbar :image="logoURL" class="top"/>
	<btn_loginVue/>
	<btn_signUpVue/>
</div>
div
<div v-show="$route.name =='Anonyme'" class="margin bg-transparent"></div>
<main id="Home-page" class="container-fluid" >
	<div>
		<!-- news -->
		<div class="news container-fluid ">
			<p class="fs-5 text-style">Latest News</p>
			<!-- frame -->
			<div class="" >
				<One_News :articles="listArticles" :articlesAnom="articleAnom" />
			</div>
		</div>
		<!-- Popular crypto -->
		<div class="container-fluid mt-4">
			<p class="fs-5 text-style">Popular cryptos</p>
				<cryptos-table class="" style="" />
		</div>
		
	</div>

</main>

</template>
<script>
import btn_loginVue from '../components/btn_login.vue'
import btn_signUpVue from '../components/btn_signUp.vue'
import One_News from '../components/One_News.vue'
import topbar from '../components/topbar.vue'
import logoURL from '../assets/logo.png'
import Cookies from 'js-cookie'
import axios from 'axios'
import 'animate.css';

export default {
	beforeCreate(){
		if(!Cookies.get('session')){
			this.$swal.fire({
			title:"Welcome to Epicoin",
			width: 600,
  			padding: '3em',
			imageUrl: 'https://epitech.bj/wp-content/uploads/2020/03/EPI-LOGO-SIGNATURE-2018.png',
			imageWidth: 100,
			imageHeight: 100,
			showClass: {
			popup: 'animate__animated animate__fadeInDown'
			},
			hideClass: {
				popup: 'animate__animated animate__fadeOutUp'
			},
        	confirmButtonText: 'Merci!',
		});
		}

	},
	beforeMount(){
		this.page()
	},
  components: { One_News ,
	topbar,btn_loginVue,btn_signUpVue,logoURL
},
  data() {
    return {
		listArticles : [],
		logoURL: logoURL,
		articleAnom : [],
	}
  },
  methods:{
	async getArticle(){
      const res = await fetch("http://localhost:4000/articles");
      const finalRes = await res.json();
      this.listArticles = finalRes.data;
    },
	async getArticleAnom(){
      await axios.get("http://localhost:4000/anonyms/anonym?name=Default")
      .then(response => {
      this.articleAnom = response.data.data.articles

      })
      .catch(error => {
        console.error(error);
      });
  
      
    },
	page(){
      if(localStorage.getItem('homee')){
        location.reload()
		localStorage.removeItem('homee')
      }
	  if(Cookies.get('session') && (localStorage.getItem('hom'))){
		setTimeout(function(){ location.reload(); }, 1000);
		localStorage.removeItem('hom')
	  }
    },

  },

  mounted(){
    this.getArticle()
	this.getArticleAnom()
  }

}
</script>

<style lang="scss">
* {
	margin: 0;
	padding: 0;
	box-sizing: border-box;
	font-family: 'Montserrat', "Open Sans", Helvetica, Arial, sans-serif; font-size: 12px;
}
.top{
	width: 100% !important;
}

.text-style{
	font-weight: bold;
}
.margin{
	position: relative;
	width: 100%;
	height: 5em;
	// margin-top: 1%;
}

.scroll-menu {
    overflow: scroll;
	width: 100vh;
  }

  .scroll-menu-items {
    display: flex;
  }


</style>