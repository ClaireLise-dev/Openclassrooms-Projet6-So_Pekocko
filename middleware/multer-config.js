//Utilistaion de multer pour enregistrer les images
const multer = require('multer');

//Modification de l'extension du fichier image
const MIME_TYPES = {
    'image/jpg': 'jpg',
    'image/jpeg': 'jpg',
    'image/png': 'png'
};

const storage = multer.diskStorage({
    destination: (req, file, callback) => {
        //Enregistrement dans le dossier images
        callback(null, 'images')
    },
    filename: (req, file, callback) => {
        //Création du nom du fichier
        const name = file.originalname.split(' ').join('_');
        const extension = MIME_TYPES[file.mimetype];
        callback(null, name + Date.now() + '.' + extension);
    }
});

module.exports = multer({ storage }).single('image');