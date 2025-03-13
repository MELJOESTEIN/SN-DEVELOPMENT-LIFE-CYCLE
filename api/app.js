const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const cors = require('cors')

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const connectRouter = require('./routes/connect')
const anonymRouter = require('./routes/anonyms')
const articlesRouter = require('./routes/articles')
const cryptoRouter = require('./routes/crypto') 

var app = express();

app.use(cors())
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//app.use('/', indexRouter);
app.use('/' , connectRouter)
app.use('/users', usersRouter); 
app.use('/anonyms', anonymRouter) 
app.use('/articles' , articlesRouter)  
app.use('/cryptos' , cryptoRouter)


module.exports = app;
