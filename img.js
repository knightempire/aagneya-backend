const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

const app = express();

// Add CORS middleware
app.use(cors());



// Create MySQL connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'test'
});

// Connect to MySQL
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL: ' + err.stack);
        return;
    }
    console.log('Connected to MySQL as id ' + connection.threadId);
});


// Multer middleware setup
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads');
    },
    filename: function(req, file, cb) {
        cb(null, 'img_' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function(req, file, cb) {
        // Check if the file is an image
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only images are allowed.'));
        }
        cb(null, true);
    }
});

// API endpoint for uploading an image
app.post('/upload', upload.single('image'), async(req, res) => {
    try {
        if (!req.file) {
            throw new Error('No file uploaded.');
        }

        // Inserting data into the table
        const insertQuery = `INSERT INTO test_img (img_path) VALUES (?)`;
        connection.query(insertQuery, [req.file.path], (error, results, fields) => {
            if (error) {
                console.error("Error inserting data: ", error);
                res.status(500).send("Error inserting data into the database");
            } else {
                console.log("Data inserted successfully");
                res.status(200).send("Image uploaded and data inserted successfully");
            }
        });
    } catch (error) {
        console.error("Error uploading image: ", error);
        res.status(500).send("Error uploading image.");
    }
});


// API endpoint for fetching all image paths
app.get('/images', (req, res) => {
    // Query to select all image paths from the database
    const selectQuery = `SELECT img_path FROM test_img`;

    // Execute the query
    connection.query(selectQuery, (error, results, fields) => {
        if (error) {
            console.error("Error fetching images: ", error);
            res.status(500).send("Error fetching images from the database");
        } else {
            // Extract image paths from the results
            const imagePaths = results.map(result => result.img_path);
            // Send the image paths as a response
            res.status(200).json(imagePaths);
        }
    });
});



// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});