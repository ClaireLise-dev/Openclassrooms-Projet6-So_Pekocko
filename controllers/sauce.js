const Sauce = require('../models/Sauce');
const fs = require('fs');

//Récupération de toutes les sauces dans la base de données (GET)
exports.getAllSauces = (req, res, next) => {
  Sauce.find()
    .then(sauces => res.status(200).json(sauces))
    .catch(error => res.status(400).json({
      error
    }));
};

//Récupération d'un seule sauce grâce à son id (GET)
exports.getOneSauce = (req, res, next) => {
  Sauce.findOne({
      _id: req.params.id
    })
    .then(sauce => res.status(200).json(sauce))
    .catch(error => res.status(404).json({
      error
    }));
};

//Création d'une sauce (POST)
exports.createSauce = (req, res, next) => {
  const sauceObject = JSON.parse(req.body.sauce);
  delete sauceObject._id;


  const sauce = new Sauce({
    ...sauceObject,
    imageUrl: `${req.protocol}://${req.get('host')}/images/${req.file.filename}`
  });
  sauce.save()
    .then(() => res.status(201).json({
      message: 'Objet enregistré !'
    }))
    .catch(error => res.status(400).json({
      error
    }));
}

//Modification d'une sauce (PUT)
exports.modifySauce = (req, res, next) => {
  const sauceObject = req.file ? {
    ...JSON.parse(req.body.sauce),
    imageUrl: `${req.protocol}://${req.get('host')}/images/${req.file.filename}`
  } : {
    ...req.body
  };
  Sauce.updateOne({
      _id: req.params.id
    }, {
      ...sauceObject,
      _id: req.params.id
    })
    .then(() => res.status(200).json({
      message: 'Objet modifié !'
    }))
    .catch(error => res.status(400).json({
      error
    }));
};

//Suppression d'une sauce (DELETE)
exports.deleteSauce = (req, res, next) => {
  Sauce.findOne({
      _id: req.params.id
    })
    .then(sauce => {
      const filename = sauce.imageUrl.split('/images/')[1];
      fs.unlink(`images/${filename}`, () => {
        Sauce.deleteOne({
            _id: req.params.id
          })
          .then(() => res.status(200).json({
            message: 'Objet supprimé !'
          }))
          .catch(error => res.status(400).json({
            error
          }));
      });
    })
    .catch(error => res.status(500).json({
      error
    }));
};

//Création like/dislike (POST)
exports.likeSauce = (req, res, next) => {
  const userId = req.body.userId;
  const like = req.body.like;
  const sauceId = req.params.id;
  Sauce.findOne({
      _id: sauceId
    })
    .then(sauce => {
      //Nouvelles valeurs à modifier
      const newValues = {
        usersLiked: sauce.usersLiked,
        usersDisliked: sauce.usersDisliked,
        likes: 0,
        dislikes: 0
      }
      //Plusieurs cas
      switch (like) {
        //Sauce like
        case 1: 
          newValues.usersLiked.push(userId);
          break;
        //Sauce dislike
        case -1: 
          newValues.usersDisliked.push(userId);
          break;
        //Annulation like/dislike
        case 0:
          if (newValues.usersLiked.includes(userId)) {
            //Si on annule le like
            const index = newValues.usersLiked.indexOf(userId);
            newValues.usersLiked.splice(index, 1);
          } else {
            //Si on annule le dislike
            const index = newValues.usersDisliked.indexOf(userId);
            newValues.usersDisliked.splice(index, 1);
          }
          break;
      };
      //Calcul du nombre de like/dislike
      newValues.likes = newValues.usersLiked.length;
      newValues.dislikes = newValues.usersDisliked.length;
      //Mis à jour de la sauce
      Sauce.updateOne({
          _id: sauceId
        }, newValues)
        .then(() => res.status(200).json({
          message: 'Sauce notée !'
        }))
        .catch(error => res.status(400).json({
          error
        }))
    })
    .catch(error => res.status(500).json({
      error
    }));
}