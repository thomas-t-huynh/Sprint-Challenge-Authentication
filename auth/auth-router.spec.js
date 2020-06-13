const request = require('supertest');
const db = require('../database/dbConfig')
const Auth = require('./auth-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


const server = require('../api/server.js'); 

const testUser = { username: "dummy", password: "secretword123"}
const preUser = { username: "thom27", password: "secretword123"}
let token

describe('server.js', () => {
    describe('POST /api/auth/register', () => {
       it('should return status code 200', async () => {
            const res = await request(server).post('/api/auth/register').send(testUser)
            expect(res.status).toBe(201)
       })
       it('should return status code 500', async () => {
            const res = await request(server).post('/api/auth/register').send(preUser)
            expect(res.status).toBe(500)
        })
    })
   
    describe('POST /api/auth/login', () => {
        it('should return status code 200', async () => {
            const res = await request(server).post('/api/auth/login').send(preUser)
            expect(res.status).toBe(200)
        })
        it('should return status code 401', async () => {
            const res = await request(server).post('/api/auth/login').send({ username: "wrong", password: "user" })
            expect(res.status).toBe(401)
        })
    })
    describe('GET /api/jokes', () => {
        it('should return status code 500', async () => {
            const res = await request(server).get('/api/jokes/')
            expect(res.status).toBe(500)
        })
        it('should return status code 200', async () => {
            const res = await request(server).get('/api/jokes/').set({'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json'})
            expect(res.status).toBe(200)
        })
    })
    beforeAll(async () => {
        await db('users').truncate()
        const hash = bcrypt.hashSync("secretword123", 10)
        const user = await Auth.add({ username: "thom27", password: hash })
        token = generateToken(user)
    })
    function generateToken(user) {
        const payload = {
            subject: user.id,
            username: user.username,
        }
    
        const options = {
            expiresIn: "2h"
        }
    
        return jwt.sign(payload, 'double chocolate chip', options)
    }
});