const bcrypt = require('bcrypt');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

//Création de nouveaux utilisateur (POST)
exports.signup = (req, res, next) => {
    //Hash du mot de passe
    bcrypt.hash(req.body.password, 10)
        .then(hash => {
            //Création du nouvel utilisateur
            const user = new User({
                email: req.body.email,
                password: hash
            });
            //Sauvegard de l'utilisateur dans la base de données
            user.save()
                .then(() => res.status(201).json({
                    message: 'Utilisateur créé !'
                }))
                .catch(error => res.status(400).json({
                    error
                }));
        })
        .catch(error => res.status(500).json({
            error
        }));
};

//Connexion d'utilisateurs déjà enregistrés dans la base de données
exports.login = (req, res, next) => {
    //Trouver l'utilisateur 
    User.findOne({
            email: req.body.email
        })
        .then(user => {
            //Si on ne trouve pas l'utilisateur
            if (!user) {
                return res.status(401).json({
                    error: 'Utilisateur non trouvé !'
                });
            }
            //Comparaison mot de passe requête/base de données
            bcrypt.compare(req.body.password, user.password)
                .then(valid => {
                    if (!valid) {
                        return res.status(401).json({
                            error: 'Mot de passe incorrect !'
                        });
                    }
                    res.status(200).json({
                        userId: user._id,
                        //Création d'un token
                        token: jwt.sign(
                            { userId: user._id },
                            'RANDOM_TOKEN_SECRET',
                            { expiresIn: '24h' }
                          )
                    });
                })
                .catch(error => res.status(500).json({
                    error
                }));
        })
        .catch(error => res.status(500).json({
            error
        }));
};