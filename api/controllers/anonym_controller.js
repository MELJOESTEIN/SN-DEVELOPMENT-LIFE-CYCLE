const AnonymModel = require("../models/anonym_model").AnonymModel
const { response } = require("express");
const responses = require("../helpers/api_responses")

function anonym_ (data){
    this.id = data._id;
    this.name = data.name,
    this.nbrArticles = data.NombreArticles,
    this.nbrCryptos = data.NombreCryptos,
    this.articles = data.articles,
    this.cryptos = data.cryptos
}


"================================================================="

exports.anonymCreate = (req , res) => {
    try{
        const anonym = new AnonymModel({
            name: req.body.name,
            NombreArticles: req.body.nbrArticles,
            NombreCryptos: req.body.nbrCryptos,
        })
    
        anonym.save((err) => {
            if (err) return responses.error(res , err)
            let anonymCreated = new anonym_(anonym)
            return responses.successData(res , "Successfully create this anonym" , anonymCreated)
        })
    } catch (err){
        return responses.error(res , err)
    }
    
} 

"================================================================="

exports.anonymSelect = (req , res) => {
     try{
        //if (req.data.role !== "admin" ) return responses.unauthorized(res , "You are not authorized to select anonyms")
        //console.log(req.query.name)
        AnonymModel.findOne({name: req.query.name} , (err , anonym) => {
            if (anonym !== null){
                if (err) return responses.error(res , err)
                let anonymCreated = new anonym_(anonym)
                return responses.successData(res , "Anonym found" , anonymCreated)

            }else{
                return responses.successData(res , "Anonym doesn't exit" , {})
            }    
        })
     }catch (err) {
        return responses.error(res , err)
     }
}

"================================================================="

exports.anonymList = (req , res) => {
    try{
        if (req.data.role !== "admin") return responses.unauthorized(res , "You are not authorized to list anonyms")
        let anonymDisplay = []
        AnonymModel.find({} , (err, anonyms) => {
            if (err) return responses.error(res , err)
            if (anonyms.length > 0){
                responses.successData(res , "anonyms" , anonyms)
            }else{
                return responses.successData(res , "anonyms is empty" , [])
            }
        })
    }catch(err){
        return responses.error(res , err)
    }
}

"================================================================="

exports.anonymUpdate = (req , res) => {
    try {
        //console.log(typeof(req.data.role))
        if (req.data.role !== "admin" ) return responses.unauthorized(res , "You are not authorized to update anonyms")
        AnonymModel.findById(req.params.id , function (err , foundAnonym){
            if (err) return responses.error(res , err)
            if (foundAnonym === null){
                return responses.notFound(res , "Anonym with this id doesn't exist")
            }else{
                const anonym = {
                    _id: foundAnonym._id,
                    name: req.body.name || foundAnonym.name,
                    NombreArticles: req.body.nbrArticles || foundAnonym.NombreArticles,
                    NombreCryptos: req.body.nbrCryptos || foundAnonym.NombreCryptos,
                }

                AnonymModel.findByIdAndUpdate(req.params.id, anonym , {} , function (err){
                    if (err) return responses.error(res , err)
                    let anonymData = new anonym_ (anonym)
                    return responses.successData(res , "Successfully update the anonym" , anonymData)
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
        if (req.data.role !== "admin" ) return responses.unauthorized(res , "You are not authorized to update anonyms")
        AnonymModel.findOne({name: "Default"} , function (err , foundAnonym){
            if (err) return responses.error(res , err)
            if (foundAnonym === null){
                return responses.notFound(res , "anonym with this id doesn't exist")
            }else{
                let foundArticle = foundAnonym.articles.filter(el =>  el.title == req.body.article.title)
                //console.log(foundArticle)
                if (foundArticle.length === 0){
                    AnonymModel.updateOne({name: "Default"}, { $push: {articles: req.body.article }} , {} , function (err){
                        if (err) return responses.error(res , err)
                        return responses.success(res , "Successfully update the article")
                    })
                }else{
                    AnonymModel.updateOne({name: "Default"}, { $pull: {articles: req.body.article }} , {} , function (err){
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
        if ( req.data.role !== "admin" ) return responses.unauthorized(res , "You are not authorized to update anonyms")
        AnonymModel.findOne({name: "Default"} , function (err , foundAnonym){
            if (err) return responses.error(res , err)
            if (foundAnonym === null){
                return responses.notFound(res , "anonym with this id doesn't exist")
            }else{
                let foundCrypto = foundAnonym.cryptos.filter(el => el.id == req.body.crypto.id)
                //console.log(foundArticle)
                if (foundCrypto.length === 0){
                    AnonymModel.updateOne({name: "Default"}, { $push: {cryptos: req.body.crypto }} , {} , function (err){
                        if (err) return responses.error(res , err)
                        return responses.success(res , "Successfully update the crypto")
                    })
                }else{
                    AnonymModel.updateOne({name: "Default"}, { $pull: {cryptos: req.body.crypto }} , {} , function (err){
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

exports.anonymDelete = (req , res) => {
    try{
        if (req.data.role !== "admin") return responses.unauthorized(res , "You are not authorized to delete this anonym")
        AnonymModel.findById(req.params.id , function (err , foundAnonym){
            if (err) return responses.error(res , err)
            if (foundAnonym === null){
                return responses.notFound(res , "Anonym with this id doesn't exist")
            }else{
                AnonymModel.findByIdAndRemove(req.params.id, function (err){
                    if (err) return responses.error(res , err)
                    return responses.success(res , "Successfully delete the anonym")
                })
            }
        })
    }catch(err){
        return responses.error(res , err)
    }
}

