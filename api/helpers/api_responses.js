exports.success = (res , msg) => {
    let data = {
        message: msg
    }

    return res.status(200).json(data)
}

"================================================================="

exports.successData = (res , msg , data) => {
    let data_ = {
        message: msg,
        data: data
    }

    return res.status(200).json(data_)
}

"================================================================="

exports.error = (res, msg) => {
    let data = {
        message: msg
    }
    
    return res.status(500).json(data)
}

"================================================================="

exports.unauthorized = (res , msg) => {
    let data = {
        message: msg
    }

    return res.status(401).json(data)
}

"================================================================="

exports.notFound = (res , msg) => {
    let data = {
        message: msg
    }

    return res.status(404).json(data)
}