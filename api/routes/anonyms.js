const express = require('express');
const router = express.Router();
const auth = require("../utils/auth").auth_jwt
const anonyms = require("../controllers/anonym_controller")

/* GET users listing. */
router.get("/",auth , anonyms.anonymList)

router.get("/anonym",  anonyms.anonymSelect)

router.post("/anonym", auth, anonyms.anonymCreate)

router.post("/update_article/", auth, anonyms.articlesUpdate)

router.post("/update_crypto/", auth, anonyms.cryptosUpdate)

router.put("/anonym/:id", auth, anonyms.anonymUpdate)

router.delete("/anonym/:id", auth, anonyms.anonymDelete)

module.exports = router;
