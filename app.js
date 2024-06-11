const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const moment = require('moment');
const fs = require('fs').promises;
const csv = require('csv-parser');
const XLSX = require('xlsx');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const fetch = require('node-fetch');
const path = require('path');



const app = express();
const port = 3000 || null;


app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


const {
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    DB_WAIT_FOR_CONNECTIONS,
    DB_CONNECTION_LIMIT,
    DB_QUEUE_LIMIT,
    SESSION_SECRET,
    JWT_SECRET,
    JWT_EXPIRY,
} = process.env;

const dbConfig = {
    host: DB_HOST,
    // port: 10379,
    port: 3306,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    waitForConnections: DB_WAIT_FOR_CONNECTIONS === 'true', // Convert string to boolean
    connectionLimit: parseInt(DB_CONNECTION_LIMIT, 10),
    queueLimit: parseInt(DB_QUEUE_LIMIT, 10),
};



// Create a MySQL pool
const pool = mysql.createPool(dbConfig);

// Serve uploaded images statically
app.use('/uploads', express.static('./uploads'));



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

// Session middleware configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

(async() => {
    try {
        // Attempt to get a connection from the pool
        const connection = await pool.getConnection();

        // If connection successful, log a success message
        console.log('Database connected successfully');

        // Release the connection back to the pool
        connection.release();
    } catch (error) {
        // Log an error message if connection fails
        console.error('Error connecting to the database:', error);
        process.exit(1); // Terminate the application process
    }
})();




//function to create token
const createtoken = (req, res, rows) => {
    // Assuming rows contain user data with a username field
    const username = rows[0].username;

    // Sign the token with the username instead of email
    const token = jwt.sign({ username: username }, JWT_SECRET, {


        expiresIn: JWT_EXPIRY,
    });

    // Assuming you are using Express and want to store the token in the session
    req.session.jwtToken = token;

    // Return the token
    return token;
};





//function to verify token
// Middleware to authenticate token and retrieve user data
// async function getUserDataByUsername(username) {
//     try {
//         // Query the database to find the user by username
//         const user = await User.findOne({ username });

//         // If user is found, return user data
//         if (user) {
//             return {
//                 id: user.id,
//                 username: user.username,
//                 email: user.email,
//                 // Add other user data properties as needed
//             };
//         } else {
//             return null; // Return null if user is not found
//         }
//     } catch (error) {
//         console.error('Error fetching user data:', error.message);
//         throw error; // Throw error for handling in the calling code
//     }
// }

const authenticateToken = async(req, res, next) => {
    try {
        // Check if Authorization header exists
        if (!req.headers.authorization) {
            return res.status(401).json({ error: 'Unauthorized' }); // Return 401 Unauthorized status
        }

        // Retrieve token from request headers and split it
        const token = req.headers.authorization.split(' ')[1];
        console.log("Token:", token); // Print token value

        // Verify token
        jwt.verify(token, "learn@1234", async(err, decodedToken) => {
            if (err) {
                console.error('Authentication error:', err.message);
                // Token is invalid or expired, send 401 Unauthorized response to client
                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                console.log('Decoded Token:', decodedToken); // Print decoded token data

                // Decode the token to get the username
                const username = decodedToken.username;
                console.log(username)

                // Retrieve user data from the database based on the username
                const userData = await getUserDataByUsername(username);

                if (!userData) {
                    // User not found in the database, send 401 Unauthorized response
                    console.error('User not found');
                    return res.status(401).json({ error: 'Unauthorized' });
                }

                // Set user information in request object
                req.user = userData;
                next(); // Proceed to next middleware
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};




//decoding the token
app.post('/api/decodeToken', async(req, res) => {
    console.log('api decode requested');
    try {
        // Extract the token from the request body
        const { token } = req.body;

        console.log(token)

        // Verify and decode the token
        const decodedToken = jwt.verify(token, JWT_SECRET);
        // console.log(decodedToken)

        // Extract username from decoded token
        const { username } = decodedToken;

        // Get a connection from the pool
        const connection = await pool.getConnection();

        try {
            // Query the database to retrieve user data based on username
            const [rows] = await connection.execute('SELECT user_id,name,username FROM users WHERE username = ?', [username]);

            // Check if user exists in the database
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Get the user data from the query results
            const userData = rows[0];
            console.log('decoded token');

            // Send user data back to the client
            res.status(200).json(userData);
        } catch (error) {
            console.error('Error querying database:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        } finally {
            // Release the connection back to the pool
            connection.release();
        }
    } catch (error) {
        // Handle any errors, such as token validation failure
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
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



app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});