const mongoose = require("mongoose");
mongoose.set('strictQuery', true);
require('dotenv').config();
//const userModel = require("../models/user_model")
const AnonymModel = require("../models/anonym_model").AnonymModel

function create_anonym () {
    try{
        const anonym = new AnonymModel({
            name: "Default",
            NombreArticles: 3,
            NombreCryptos: 3,
        })
    
        anonym.save((err) => {
            if (err) {
                console.log(err)
            }else{
                console.log("Default anonym successfully created")
            }
        })
    } catch (err){
        console.log(err)
    }
    
} 


mongoose.connect(process.env.DB_URI)
        .then(() =>{
            console.log("Successfully create database"); 
            let db = mongoose
            require("../models/user_model")
            require("../models/anonym_model")

            create_anonym ()


            //db.connection.db.addUser(process.env.DB_USER , process.env.DB_PASS)
            console.log("Use Ctrl+C to continue")

        })
        .catch(err => console.log(err));
