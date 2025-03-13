const axios = require("axios")
const { response } = require("express");
const responses = require("../helpers/api_responses")
const articles_api = "https://newsapi.org/v2/everything?q=cryptocurrency bitcoin ethereum&from=2022&sortBy=popularity&apiKey=26dc81f4cd664fd4a77b034a6ea7999d"

exports.articles = (req , res) => {
    try{
        axios.get(articles_api).then(response =>{
        //console.log(response)
            return responses.successData(res , "Articles" , response.data.articles)
        }).catch(err => {
            res.send(err)
        })
    } catch (err){
        return responses.error(res , err)
    }
    

}

