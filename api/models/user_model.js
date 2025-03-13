const db = require("../database/db_instance").db_conn

const UserSchema = db.Schema({

    avatar: {
        type: String
    },

    lastname: {
        type: String,
        required: true
    },
    
    firstname: {
        type: String,
        required: true
    },

    username: {
        type: String,
        required: true,
        unique: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    }, 

    password: {
        type: String,
        required: true,
        min: [8 , "Must be 8 character, got {VALUE}"]
    },

    role: {
        type: String,
        require: true,
        enum:{
            values: ["admin" , "user"],
            message: "The role {VALUE} not exist"
        }
    },

    articles: [],

    cryptos: []
})

exports.UserModel = db.model("Users" , UserSchema)

//let UserInst = users({username: UserObj.username, email: UserObj.email, role: UserObj.role, PrefArticles: UserObj.PrefArticles, PrefCryptos: UserObj.PrefCryptos })

 