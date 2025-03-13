var express = require('express');
var router = express.Router();
const controller = require("../controllers/connect_controller")

router.post("/register" , controller.register)

router.post("/login" , controller.login)

module.exports = router;
