const jwt = require("jsonwebtoken");
const crypto = require("crypto");

"================================================================="

exports.gen_jwt_token  = function (data){
    //console.log(process.env.TOKEN_SECRET)
    return jwt.sign(data , process.env.TOKEN_SECRET)
}

"================================================================="

exports.auth_jwt = function (req , res  , next){
    let auth_header = req.headers["authorization"]

    let token = auth_header && auth_header.split(" ")[1]

    //console.log(token)
    //console.log("cc")

    jwt.verify(token , process.env.TOKEN_SECRET , (err , data) => {

        if (err) return res.sendStatus(401)

        req.data = data

        next()
    })
}

"================================================================="

function encrypt (text , text_encoding){
    const cipher = crypto.createCipheriv(process.env.CRYPTO_ALGO , Buffer.from(process.env.CRYPTO_KEY , "base64") , Buffer.from(process.env.INIT_VECTOR , "base64"))

    let encrypted_data = cipher.update(text , text_encoding , "hex")

    encrypted_data += cipher.final("hex")

    return encrypted_data
}

"================================================================="

function decrypt (encrypted_data , text_encoding){
    const uncipher = crypto.createDecipheriv(process.env.CRYPTO_ALGO , Buffer.from(process.env.CRYPTO_KEY , "base64") , Buffer.from(process.env.INIT_VECTOR , "base64"))

    let decrypted_data = uncipher.update(encrypted_data , "hex" , text_encoding)

    decrypted_data += uncipher.final(text_encoding)

    return decrypted_data

}

"================================================================="

exports.decrypt = decrypt
exports.encrypt = encrypt