// Imports
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express()

// Config JSON response
app.use(express.json());

// Models
const User = require('./models/User');

// Open Route = Public Route
app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem vindo a nossa API!"})
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    // Check if user exists
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: "Usuário não cadastrado" })
    }

    res.status(200).json({ user })

})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: "Acesso negado!" })
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()

    }
    catch (err) {
        res.status(400).json({ msg: "Token inválido."})
    }
}

// Register User
app.post('/auth/resgister', async(req, res) => {
    
    const {name, email, password,confirmpassword} = req.body

    // Validations
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatorio!' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatorio!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatoria!' })
    }
    if (!confirmpassword) {
        return res.status(422).json({ msg: 'Confirme a senha!' })
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não são iguais!' })
    }
    
    // Check if user exists
    const userExists = await User.findOne({ email: email})

    if (userExists) {
        return res.status(422).json({ msg: 'Usuário já cadastrado' })
    }

    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create User
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save();
        return res.status(201).json({ msg: "Usuário criado com sucesso!" })

    }
    catch (err) {
        console.log(err);
        return res.status(500).json({ msg: "Aconteceu um erro no servidor, tente mais tarde"});
    }

});

// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body

    // Validations
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatorio!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatoria!' })
    }

     // Check if user exists
    const user = await User.findOne({ email: email})

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não cadastrado' })
    }

    // Check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" });
    }

    try {

        const secret = process.env.SECRET
        const token = jwt.sign(
            {
                id: user._id
            },
            secret,
        )

        return res.status(200).json({ msg: "Autencicação realizada com sucesso", token});
    }
    catch (err) {
        console.log(err);

        return res.status(500).json({ msg: "Aconteceu um erro no servidor, tende novamente mais tarde." })
    };

})


// Credencials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.
    connect(`mongodb+srv://${dbUser}:${dbPass}@fluxodecaixa.flfxokv.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000);
        console.log("Conectou ao banco");
    })
    .catch((err) => console.log(err))
