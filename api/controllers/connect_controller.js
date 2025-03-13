const UserModel = require("../models/user_model").UserModel
const { response } = require("express");
const bcrypt = require("bcrypt")
const responses = require("../helpers/api_responses")
const auth = require("../utils/auth")

function user_ (data){
    this.id = data._id;
    this.avatar = data.avatar;
    this.lastname = data.lastname;
    this.firstname = data.firstname;
    this.username = data.username;
    this.email = data.email;
    this.role = data.role;
    this.articles = data.articles,
    this.cryptos = data.cryptos
}


exports.register = (req , res) => {
    try{
        UserModel.findOne({email: req.body.email , username: req.body.username}, function(err , user){
            if (user) return responses.unauthorized(res , "The username or the email already exists")
        
        //console.log(req.body.username)
        bcrypt.hash(req.body.password,10,function(err, hash) {
            const user = new UserModel({
                avatar: null,
                lastname: req.body.lastname,
                firstname: req.body.firstname,
                username: req.body.username,
                email: req.body.email,
                password: hash,
                role: req.body.role,
                articles: req.body.articles,
                cryptos: req.body.cryptos
            })
            //console.log(user._id)
        
            user.save((err) => {
                //console.log(user._id)
                if (err) return responses.error(res , err)
                let userCreated = new user_(user)
                return responses.successData(res , "Successfully create this user" , userCreated)
            })
        })
        })
    } catch (err){
        return responses.error(res , err)
    }

}

exports.login = (req , res) => {
    UserModel.findOne({email : req.body.email}).then(user => {
        bcrypt.compare(req.body.password, user.password, function(err , valid){
            if (err) return responses.error(res , err)
            if (valid){
                const data = {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            const token = auth.gen_jwt_token(data)
            return responses.successData(res , "Successfully login" , {token: token})
            }
        })
}).catch((err) => {
    console.log(err)
})
}