const db = require('../database/dbconfig')

module.exports = {
    add,
    findBy
}

function add(user) {
    return db('users').insert(user)
        .then(() => user )
}

function findBy(username) {
    return db('users').where({username})
}