const express = require('express')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const randtoken = require('rand-token')
const passport = require('passport')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt

const  refreshTokens = {}
const SECRET = "SECRETO_PARA_ENCRYPTACION"

const app = express()

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))
app.use(passport.initialize())
app.use(passport.session())

// it is better to identificate user by id then by name

passport.serializeUser((user, done) => done(null, user.username))

// it is not needed for JWT strategy only:
//passport.deserializeUser((username, done) => done(null, username))

const opts = {}

// Setup JWT options
opts.jwtFromRequest = ExtractJwt.fromAuthHeader()
opts.secretOrKey = SECRET

passport.use(new JwtStrategy(opts, (jwtPayload, done) => {
    // If the token has expiration, raise unauthorized
    const expirationDate = new Date(jwtPayload.exp * 1000)
    if (expirationDate < new Date()) {
        return done(null, false)
    }
    const user = jwtPayload
    done(null, user)
}))

app.post('/login', (req, res, next) => {
    const username = req.body.username
    const password = req.body.password

    const user = {
        username,
        role: 'admin'
    }

    const token = jwt.sign(user, SECRET, {expiresIn: 300})
    const refreshToken = randtoken.uid(256)
    refreshTokens[refreshToken] = username
    res.status(200).json({
        token: 'JWT ' + token,
        refreshToken
    })
})

app.post('/token', (req, res, next) => {
    const username = req.body.username
    const refreshToken = req.body.refreshToken

    if ((refreshToken in refreshTokens) && (refreshTokens[refreshToken] === username)) {
        const user = {
            username,
            role: 'admin'
        }
        const token = jwt.sign(user, SECRET, {expiresIn: 300})
        res.status(200).json({token: 'JWT ' + token})
    } else {
        res.status(401).json({message: 'Invalid credentials'})
    }
})

// Check for admin permissions to reject refresh token
app.post('/token/reject', (req, res, next) => {
    const refreshToken = req.body.refreshToken
    if (refreshToken in refreshTokens) {
        delete refreshTokens[refreshToken]
    }
    res.status(200).json({message: 'Successfully rejected'})
})

app.get('/test_jwt', passport.authenticate('jwt'), (req, res) => {
    res.json({success: 'You are authenticated with JWT!', user: req.user})
})

app.listen(8999)