const db = require("../database/db_instance").db_conn

const AnonymSchema = db.Schema({

    name: {
        type: String,
        require: true,
        unique: true
    },
    
    NombreArticles: Number,

    NombreCryptos: Number, 
    
    articles: [],

    cryptos: []
})

exports.AnonymModel = db.model("Anonym" , AnonymSchema)