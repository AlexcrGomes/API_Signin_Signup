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

// Credencials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

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
        res.status(201).json({ msg: "Usuário criado com sucesso!" })

    }
    catch (err) {
        console.log(err);
        res.status(500).json({ msg: "Aconteceu um erro no servidor, tente mais tarde"});
    }

});


mongoose.
    connect(`mongodb+srv://${dbUser}:${dbPass}@fluxodecaixa.flfxokv.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000);
        console.log("Conectou ao banco");
    })
    .catch((err) => console.log(err))
