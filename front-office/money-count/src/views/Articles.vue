<template>
  <main class="Article-page" >
    
    <div class="button my-4" style="display:flex; justify-content: space-between;">
      <button @click="page" class="btn btn-warning">All Articles</button>
      <form class="" style="display:flex;">
        <input class="form-control me-2" type="text" placeholder="Search" aria-label="Search" @input="updateFilter()" v-model="searchVa">
        <button v-bind:disabled="isDisabled" class="btn btn-outline-success" type="text">Search</button>
      </form>
    </div>
    <div class="Hight overflow-scroll">
      
    <div class="all_articles p-2" v-for="(articleA) in filteredArticles" :key="articleA.source.id" >
      <One_Article v-if="searchVa" @click="articleInfo(articleA.url)" :image="articleA.urlToImage" :thematic="articleA.source.name" :title="articleA.title" :date="articleA.publishedAt" :resumer="articleA.description" class="cursor-auto" />
    </div>
    <div class="all_articles p-2" v-for="(article, index) in listArticles" :key="article.source.id">
      <checkbox :value="value" :index="index" v-if="this.role === 'admin' || this.isInDatabase" @click="check(index, value)"  :state="article.isChecked||false" :checkIfInDatabase="checkIfInDatabase"/>
  
      <One_Article v-if="!searchVa" @click="articleInfo(article.url)" :image="article.urlToImage" :thematic="article.source.name" :title="article.title" :date="article.publishedAt" :resumer="article.description" class="cursor-auto"/>
    </div> 
  
  </div>
  </main>
</template>
 
<script>

import SearchInput from 'vue-search-input'
import 'vue-search-input/dist/styles.css'
import checkbox from '../components/checkbox.vue';
import One_Article from '../components/One_Article.vue';
import Cookies from 'js-cookie'
import VueJwtDecode from 'vue-jwt-decode';
import axios from 'axios';

export default {
  
  components: { One_Article , checkbox,SearchInput},
  data() {
    return {
      listArticles : [],
      role:'',
      searchVa:"",
      filteredArticles: [],
      isDisabled: true,
	  };
  },
  created() {
    this.getArticle()
    
  },

// https://newsapi.org/v2/everything?q=cryptocurrency bitcoin ethereum&from=2022&sortBy=popularity&apiKey=26dc81f4cd664fd4a77b034a6ea7999d
  methods: {
    async getArticle(){

      Promise.all([
        await axios.get('http://localhost:4000/anonyms/anonym?name=Default'),
        await axios.get('http://localhost:4000/articles')
      ]).then(([response1, response2]) => {
        var isInDatabase = response1.data.data.articles
        var articles = response2.data.data
        var articlesReadOnly = response2.data.data
        for(let t = 0; t < isInDatabase.length; t++){
            let index = articlesReadOnly.map(function(e) { return JSON.stringify(e); }).indexOf(JSON.stringify(isInDatabase[t]))
            if(index !== -1){
              articles[index].isChecked = true
            }     
        }
        this.listArticles = articles
        }).catch(error => {
        console.log(error);
      });
    },
     async check(index, value){
      let modifiedObj = {...this.listArticles[index], isChecked: undefined}
      console.log(modifiedObj)
      await axios({
        method: "post",
        url: ' http://localhost:4000/anonyms/update_article',
        headers: {
          "authorization": 'Bearer ' + Cookies.get('session')
        },
        data: {
            article : modifiedObj
        }
      }).then(response => {
          this.response = response
          // console.log(this.listArticles[index])
          
      }).catch(e => {
          this.response = e
          console.log(this.response)
      })

    },
    sessionRecup(){
      const session = Cookies.get('session');
      const dec = VueJwtDecode.decode(session);
      this.role = dec.role
    },
    page(){
      localStorage.setItem('name', 'refresh')
      if(localStorage.getItem('name')){
        location.reload()
      }
    },
    articleInfo(url){
      window.open(url, '_blank', 'noreferrer');
    },

  },
  
  mounted(){
    this.sessionRecup()
  },
  computed: {
   
    updateFilter(){
      let filteredArray = [];
      for (let i = 0; i < this.listArticles.length; i++) {
          if (this.listArticles[i].title.toLowerCase().includes(this.searchVa.toLowerCase())) {
              filteredArray.push(this.listArticles[i]);
          }
      }
      this.filteredArticles = filteredArray
    }
        
    
  }
}
</script>

<style lang="scss">
*{
  text-align: justify;
 
}
.all_articles{
  cursor:pointer;
  overflow: scroll;
}
.Hight{
  height: 75vh;
}
</style>