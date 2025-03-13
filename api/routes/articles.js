var express = require('express');
var router = express.Router();
const controller = require("../controllers/article_controller")

router.get("/" , controller.articles)

module.exports = router;
