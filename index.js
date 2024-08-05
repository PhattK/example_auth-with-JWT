const cors = require("cors");
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: ["http://localhost:8888"],
  }),
);
app.use(cookieParser());

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  }),
);

const port = 8000;
const secret = "mysecret";

let conn = null;

const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "tutorial",
  })
}

app.post('/api/register', async (req, res) => {
    const {email, password} = req.body
    const [rows] = await conn.query("SELECT * FROM users WHERE email = ?", email);
    if (rows.length) {
        return res.status(400).send({ message: "Email is already registered" });
    }

    const hash = await bcrypt.hash(password, 10)

    const userData = {
        email,
        password: hash
    }

    try {
        const result = await conn.query('INSERT INTO users SET ?', userData)
    } catch (error) {
        console.log(error)
        req.status(400).json({
            message: "Insert Fail",
            error
        })
    }

    res.status(201).send({
        message: "Registered Complete"
    })
})

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body
  
    const [result] = await conn.query("SELECT * from users WHERE email = ?", email)
    if (!result.length) {
        return res.status(400).send({ message: "Email not found" });
    }
    const user = result[0]
    const match = await bcrypt.compare(password, user.password)
    if (!match) {
      return res.status(400).send({ message: "Invalid email or password" })
    }

    const token = jwt.sign({ email, role: 'admin' }, secret, { expiresIn: '1h' })

    res.send({ 
        message: "Login successful" ,
        token
    })
})

app.get('/api/users', async (req, res) => {
    try {
        const authHeader = req.headers['authorization']
        let authToken = ''
        if (authHeader) {
            authToken = authHeader.split(' ')[1]
        }
        const user = jwt.verify(authToken, secret)
        const [checkResults] = await conn.query('SELECT * FROM users WHERE email = ?', user.email)
        if (!checkResults[0]) {
            throw {message: 'user not found'}
        }
        const [results] = await conn.query('SELECT * FROM users')
        res.json({
            users: results
        })
    } catch (error) {
        console.log('error', error)
        res.status(403).json({
            message: 'auth fail',
            error
        })
    }
})

app.listen(port, async () => {
    await initMySQL()
    console.log("Server started at port 8000")
})