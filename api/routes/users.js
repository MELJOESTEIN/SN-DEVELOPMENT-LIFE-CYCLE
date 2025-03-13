const express = require('express');
const router = express.Router();
const auth = require("../utils/auth").auth_jwt
const users = require("../controllers/user_controller")

/* GET users listing. */
router.get("/", auth,  users.userList)

router.get("/user",auth, users.userSelect)

router.post("/user", auth, users.userCreate)

router.post("/update_article/:id", auth, users.articlesUpdate)

router.post("/update_crypto/:id", auth, users.cryptosUpdate)

router.put("/user/:id", auth,users.userUpdate)

router.delete("/user/:id", auth, users.userDelete )


module.exports = router;
