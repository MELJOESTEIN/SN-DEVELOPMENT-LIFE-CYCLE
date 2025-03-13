const UserModel = require("../models/user_model").UserModel
const { response } = require("express");
const responses = require("../helpers/api_responses")
const bcrypt = require("bcrypt")

function user_ (data){
    this.id = data._id;
    this.avatar = data.avatar;
    this.lastname = data.lastname;
    this.firstname = data.firstname,
    this.username = data.username;
    this.email = data.email;
    this.role = data.role;
    this.articles = data.articles;
    this.cryptos = data.cryptos;
}


"================================================================="

exports.userCreate = (req , res) => {
    try{
        const user = new UserModel({
            avatar: null,
            lastname: req.body.lastname,
            firstname: req.body.firstname,
            username: req.body.username,
            email: req.body.email,
            password: req.body.password,
            role: req.body.role
        })
    
        user.save((err) => {
            if (err) return responses.error(res , err)
            let userCreated = new user_(user)
            return responses.successData(res , "Successfully create this user" , userCreated)
        })
    } catch (err){
        return responses.error(res , err)
    }
    
} 

"================================================================="

exports.userSelect = (req , res) => {
     try{
        if ((req.data.username !== req.query.username) && (req.data.role !== "admin" )) return responses.unauthorized(res , "You are not authorized to select users")
        UserModel.findOne({username: req.query.username} , (err , user) => {
            if (user !== null){
                if (err) return responses.error(res , err)
                let userCreated = new user_(user)
                return responses.successData(res , "User found" , userCreated)

            }else{
                return responses.notFound(res , "User doesn't exit" , {})
            }    
        })
     }catch (err) {
        return responses.error(res , err)
     }
}

"================================================================="

exports.userList = (req , res) => {
    try{
        if (req.data.role !== "admin") return responses.unauthorized(res , "You are not authorized to list users")
        let userDisplay = []
        UserModel.find({} , (err, users) => {
            if (err) return responses.error(res , err)
            if (users.length > 0){
                for (let user of users){
                    let user_d = new user_(user)
                    userDisplay.push(user_d)
                }
                responses.successData(res , "users" , userDisplay)
            }else{
                return responses.successData(res , "users is empty" , [])
            }
        })
    }catch(err){
        return responses.error(res , err)
    }
}

"================================================================="

exports.userUpdate = (req , res) => {
    try {
        //console.log(typeof(req.data.role))
        if ((req.data.id !== req.params.id) && (req.data.role !== "admin" )) return responses.unauthorized(res , "You are not authorized to update users")
        UserModel.findById(req.params.id , function (err , foundUser){
            if (err) return responses.error(res , err)
            if (foundUser === null){
                return responses.notFound(res , "User with this id doesn't exist")
            }else{
                if (req.body.password){
                    bcrypt.hash(req.body.password,10,(err , hash) => {
                        if (err) return responses.error(res , "Erreur lors de la mise à jour")
                        req.body.password = hash
                    })
                }
                
                const user = {
                    _id: foundUser._id,
                    avatar: req.body.avatar || foundUser.avatar,
                    lastname: req.body.lastname || foundUser.lastname,
                    firstname: req.body.firstname || foundUser.firstname,
                    username: req.body.username || foundUser.username,
                    email: req.body.email || foundUser.email,
                    password: req.body.password || foundUser.password,
                    role: req.body.role || foundUser.role
                }

                UserModel.findByIdAndUpdate(req.params.id, user , {} , function (err){
                    if (err) return responses.error(res , err)
                    let userData = new user_ (user)
                    return responses.successData(res , "Successfully update the user" , userData)
                })
            } 
        })

    }catch(err){
        return responses.error(res , err)
    }
}

"================================================================="

exports.articlesUpdate = (req , res) => {
    try {
        //console.log(typeof(req.data.role))
        if ((req.data.id !== req.params.id) && (req.data.role !== "admin" )) return responses.unauthorized(res , "You are not authorized to update users")
        UserModel.findById(req.params.id , function (err , foundUser){
            if (err) return responses.error(res , err)
            if (foundUser === null){
                return responses.notFound(res , "User with this id doesn't exist")
            }else{
                let foundArticle = foundUser.articles.filter(el => el == req.body.article)
                //console.log(foundArticle)
                if (foundArticle.length === 0){
                    UserModel.updateOne({_id: req.params.id}, { $push: {articles: req.body.article }} , {} , function (err){
                        if (err) return responses.error(res , err)
                        return responses.success(res , "Successfully update the article")
                    })
                }else{
                    UserModel.updateOne({_id: req.params.id}, { $pull: {articles: req.body.article }} , {} , function (err){
                        if (err) return responses.error(res , err)
                        return responses.success(res , "Successfully dupdate the article")
                    })
                }
                
            }
        })

    }catch(err){
        return responses.error(res , err)
    }
}

"================================================================="

exports.cryptosUpdate = (req , res) => {
    try {
        //console.log(typeof(req.data.role))
        if ((req.data.id !== req.params.id) && (req.data.role !== "admin" )) return responses.unauthorized(res , "You are not authorized to update users")
        UserModel.findById(req.params.id , function (err , foundUser){
            if (err) return responses.error(res , err)
            if (foundUser === null){
                return responses.notFound(res , "User with this id doesn't exist")
            }else{
                let foundCrypto = foundUser.cryptos.filter(el => el == req.body.crypto)
                //console.log(foundArticle)
                if (foundCrypto.length === 0){
                    UserModel.updateOne({_id: req.params.id}, { $push: {cryptos: req.body.crypto }} , {} , function (err){
                        if (err) return responses.error(res , err)
                        return responses.success(res , "Successfully update the crypto")
                    })
                }else{
                    UserModel.updateOne({_id: req.params.id}, { $pull: {cryptos: req.body.crypto }} , {} , function (err){
                        if (err) return responses.error(res , err)
                        return responses.success(res , "Successfully dupdate the crypto")
                    })
                }
                
            }
        })

    }catch(err){
        return responses.error(res , err)
    }
}

"================================================================="


exports.userDelete = (req , res) => {
    try{
        if (req.data.role !== "admin") return responses.unauthorized(res , "You are not authorized to delete this user")
        UserModel.findById(req.params.id , function (err , foundUser){
            if (err) return responses.error(res , err)
            if (foundUser === null){
                return responses.notFound(res , "User with this id doesn't exist")
            }else{
                UserModel.findByIdAndRemove(req.params.id, function (err){
                    if (err) return responses.error(res , err)
                    return responses.success(res , "Successfully delete the user")
                })
            }
        })
    }catch(err){
        return responses.error(res , err)
    }
}

