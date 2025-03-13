const axios = require("axios")
const { response } = require("express");
const responses = require("../helpers/api_responses")
const crypto_api = "https://api.coingecko.com/api/v3/coins/markets?vs_currency=eur&order=market_cap_desc&per_page=100&page=1&sparkline=false"

exports.cryptos = (req , res) => {
    try{
        axios.get(crypto_api).then(response =>{   
            return responses.successData(res , "Crypto" , response.data)
        }).catch(err => {
            res.send(err)
        })
    } catch (err){
        return responses.error(res , err)
    }
    
}

