var express = require('express');
var router = express.Router();
const controller = require("../controllers/crypto_controller") 

router.get("/" , controller.cryptos);

module.exports = router;
