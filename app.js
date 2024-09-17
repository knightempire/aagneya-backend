const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { google } = require("googleapis");
const stream = require("stream");



const app = express();
const upload = multer();

const port = 3000 || null;


app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

require('dotenv').config();
const {
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    DB_WAIT_FOR_CONNECTIONS,
    DB_CONNECTION_LIMIT,
    DB_QUEUE_LIMIT,
    DB_PORT,
    SESSION_SECRET,
    JWT_SECRET,
    JWT_EXPIRY,
} = process.env;

const dbConfig = {
    host: DB_HOST,
    port: DB_PORT,
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
// app.use('/uploads', express.static('./uploads'));
// app.use('/pdf', express.static('./pdf'));



// Multer middleware setup
// const storage = multer.diskStorage({
//     destination: function(req, file, cb) {
//         cb(null, 'uploads');
//     },
//     filename: function(req, file, cb) {
//         cb(null, 'img_' + Date.now() + path.extname(file.originalname));
//     }
// });

// const upload = multer({
//     storage: storage,
//     fileFilter: function(req, file, cb) {
//         // Check if the file is an image
//         if (!file.mimetype.startsWith('image/')) {
//             return cb(new Error('Only images are allowed.'));
//         }
//         cb(null, true);
//     }
// });

// Multer middleware setup for PDFs
// const pdfStorage = multer.diskStorage({
//     destination: function(req, file, cb) {
//         cb(null, 'pdf'); // Directory where uploaded PDF files will be stored
//     },
//     filename: function(req, file, cb) {
//         cb(null, 'doc_' + Date.now() + path.extname(file.originalname)); // Rename the PDF file if needed
//     }
// });

// const uploadPdf = multer({
//     storage: pdfStorage,
//     fileFilter: function(req, file, cb) {
//         // Check if the file is a PDF
//         if (!file.mimetype.startsWith('application/pdf')) {
//             return cb(new Error('Only PDF files are allowed.'));
//         }
//         cb(null, true);
//     }
// });


// Multer middleware setup for images and PDFs
// const storage1 = multer.diskStorage({
//     destination: function(req, file, cb) {
//         if (file.mimetype.startsWith('image/')) {
//             cb(null, 'uploads');
//         } else if (file.mimetype.startsWith('application/pdf')) {
//             cb(null, 'pdf');
//         }
//     },
//     filename: function(req, file, cb) {
//         if (file.mimetype.startsWith('image/')) {
//             cb(null, 'img_' + Date.now() + path.extname(file.originalname));
//         } else if (file.mimetype.startsWith('application/pdf')) {
//             cb(null, 'doc_' + Date.now() + path.extname(file.originalname));
//         }
//     }
// });

// const upload1 = multer({
//     storage: storage1,
//     fileFilter: function(req, file, cb) {
//         if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('application/pdf')) {
//             return cb(new Error('Only images and PDFs are allowed.'));
//         }
//         cb(null, true);
//     }
// });



const KEYFILEPATH = path.join(__dirname, "cred.json");
const SCOPES = ["https://www.googleapis.com/auth/drive"];


const auth = new google.auth.GoogleAuth({
    keyFile: KEYFILEPATH,
    scopes: SCOPES,
});


const uploadFile = async(fileObject, name) => {
    const bufferStream = new stream.PassThrough();
    bufferStream.end(fileObject.buffer);

    const fileExtension = path.extname(fileObject.originalname);
    const fileName = `${name}${fileExtension}`;

    const { data } = await google.drive({ version: "v3", auth }).files.create({
        media: {
            mimeType: fileObject.mimetype,
            body: bufferStream,
        },
        requestBody: {
            name: fileName,
            parents: ["1NOS8Xy8QZq7YPPRzNLSgEhJH4NmV9vwd"], // Replace with your folder ID
        },
        fields: "id,name",
    });

    const url = `https://drive.google.com/file/d/${data.id}/view`;
    console.log(`Uploaded file ${data.name} ${data.id}`);
    console.log(`URL: ${url}`);

    return url;
};


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
    // Assuming rows contain user data with a roll_no field
    const roll_no = rows[0].roll_no;

    // Sign the token with the roll_no instead of email
    const token = jwt.sign({ roll_no: roll_no }, JWT_SECRET, {
        expiresIn: JWT_EXPIRY,
    });

    // Assuming you are using Express and want to store the token in the session
    req.session.jwtToken = token;

    // Return the token
    return token;
};






//function to verify token
// Middleware to authenticate token and retrieve user data
// async function getUserDataByroll_no(roll_no) {
//     try {
//         // Query the database to find the user by roll_no
//         const user = await User.findOne({ roll_no });

//         // If user is found, return user data
//         if (user) {
//             return {
//                 id: user.id,
//                 roll_no: user.roll_no,
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

const authenticateToken = (req, res, next) => {
    try {
        // Check if Authorization header exists
        if (!req.headers.authorization) {
            return res.redirect('#'); // Redirect to login page
        }

        // Retrieve token from request headers and split it
        const token = req.headers.authorization.split(' ')[1];
        // console.log("Token:", token); // Print token value

        // Verify token
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error('Authentication error:', err.message);
                // Token is invalid or expired, send 401 Unauthorized response to client
                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                req.user = decoded; // Set decoded information in request object
                // console.log('Decoded user:', decoded);
                next(); // Proceed to next middleware
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};




app.post('/api/decodeToken', [authenticateToken, async(req, res) => {
    console.log('api decode requested');
    try {
        // Extract the token from the request body
        const { token } = req.body;

        // Verify and decode the token
        const decodedToken = jwt.verify(token, JWT_SECRET);

        // Extract roll_no from decoded token
        const { roll_no } = decodedToken;

        // Check if roll_no is defined
        if (!roll_no) {
            return res.status(400).json({ error: 'roll_no not found in token' });
        }

        // Get a connection from the pool
        const connection = await pool.getConnection();

        try {
            // Query the database to retrieve user data based on roll_no
            const [rows] = await connection.execute('SELECT l.roll_no, l.is_active, l.role_id, l.spl_role, p.name FROM login l LEFT JOIN profile p ON l.roll_no = p.roll_no WHERE l.roll_no = ?', [roll_no]);

            // Check if user exists in the database
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Get the user data from the query results
            const userData = rows[0];

            // Determine if profile exists
            userData.profile = rows[0].name && rows[0].name !== 'Unknown' ? 1 : 0;
            console.log(userData.profile)

            // Set name to 'User' if it's null or undefined
            userData.name = rows[0].name || 'User';

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
}]);


// Route for login
app.post('/api/login', async(req, res) => {
    const { roll_no, password } = req.body;

    try {
        console.log('API login requested');

        // Query the database to check if the provided roll number exists in the login table
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE roll_no = ?', [roll_no]);

        if (existingUser.length === 0) {
            // If the roll number doesn't exist in the login table, return an error
            console.log("No user found");
            return res.status(400).json({ error: 'Invalid roll number' });
        }

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, existingUser[0].password);

        if (!isPasswordValid) {
            // If the password is incorrect, return an error
            console.log("Invalid password");
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Check if the user is active
        const isActive = existingUser[0].is_active;

        if (isActive === 0) {
            // If the user is not active, return a message
            console.log("User is no longer active");
            return res.status(400).json({ error: 'You are no longer an active user' });
        }

        // Assuming you want to retrieve role_id from existingUser
        const { role_id } = existingUser[0];

        // Check if the roll number exists in the profile table
        const [existingProfile] = await pool.execute('SELECT * FROM profile WHERE roll_no = ?', [roll_no]);
        let profileExists = 0;

        console.log(existingProfile)
        if (existingProfile.length > 0) {
            // If the roll number exists in the profile table, set profileExists to 1
            const profileData = existingProfile[0];
            if (profileData.name && profileData.name !== "Unknown") {
                profileExists = 1;
            }
        }

        // Call function to create token
        const token = createtoken(req, res, existingUser);
        console.log("Token:", token);

        // Send response
        res.json({ isValid: true, profile: profileExists, token, role_id });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




// Route for user registration
app.post('/api/register', [authenticateToken, async(req, res) => {
    const { roll_no, date, role_id, sport_id, year, gender } = req.body;
    try {
        console.log('API registration requested');
        // Check if the roll number already exists (case-insensitive check)
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = LOWER(?)', [roll_no]);
        // Check if any rows were returned
        if (existingUser.length > 0) {
            console.log('User with the same roll number already exists');
            return res.status(400).json({ error: 'User with the same roll number already exists' });
        }
        // Set password to roll_nNo
        const password = roll_no;
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Insert new user into the login table
        const loginResult = await pool.execute('INSERT INTO login (roll_no, password, is_active, date, role_id) VALUES (?, ?, ?, ?, ?)', [roll_no, hashedPassword, 1, date, role_id]);
        // Insert sport_id and year into the profile table
        const profileResult = await pool.execute('INSERT INTO profile (roll_no, sport_id, year,gender) VALUES (?, ?, ?, ?)', [roll_no, sport_id, year, gender]);
        // Send response
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




// Route for adding sports
app.post('/api/addsports', [authenticateToken, async(req, res) => {
    const { sport_name } = req.body;

    try {
        console.log('API addsports requested');

        // Convert sport_name to lowercase
        const lowercaseSportName = sport_name.toLowerCase();

        // Check if the sport already exists (case-insensitive)
        const [existingSport] = await pool.execute('SELECT * FROM sports WHERE LOWER(sport_name) = ?', [lowercaseSportName]);

        if (existingSport.length > 0) {
            return res.status(400).json({ error: 'Sport already exists' });
        }

        // Get the maximum sport_id from the database
        const [maxSportId] = await pool.execute('SELECT MAX(sport_id) AS maxSportId FROM sports');

        // Calculate the next sport_id
        const nextSportId = maxSportId[0].maxSportId + 1 || 1; // Handle the case where there are no existing sports

        // Insert new sport into the sports table with the calculated sport_id and lowercase sport_name
        const result = await pool.execute('INSERT INTO sports (sport_id, sport_name) VALUES (?, ?)', [nextSportId, lowercaseSportName]);

        // Send response
        res.json({ success: true, message: 'Sport added successfully' });
    } catch (error) {
        console.error('Error adding sport:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// API endpoint for displaying sports data
app.get('/api/displaysports', async(req, res) => {
    try {
        console.log('API displaysports requested');

        // Retrieve data from the sports table
        const [sportsData] = await pool.execute('SELECT * FROM sports ORDER BY sport_name');
        console.log(sportsData)

        // Send response with the retrieved sports data
        res.json({ success: true, sports: sportsData });
    } catch (error) {
        console.error('Error displaying sports data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for adding security information
app.post('/api/addsecurity', [authenticateToken, async(req, res) => {
    try {
        console.log('API addsecurity requested');

        // Destructure roll_no and formData from req.body
        const { roll_no, formData } = req.body;

        // Destructure hospital_born, school, fav_friend from formData
        const { hospital_born, school, fav_friend } = formData;

        // Convert roll_no, hospital_born, school, and fav_friend to lowercase
        const loweredRollNo = roll_no.toLowerCase();
        const loweredHospitalBorn = hospital_born.toLowerCase();
        const loweredSchool = school.toLowerCase();
        const loweredFavFriend = fav_friend.toLowerCase();


        // Insert new security information into the qa table
        const result = await pool.execute(
            'UPDATE qa SET hospital_born = ?, school = ?, fav_friend = ? WHERE roll_no = ?', [loweredHospitalBorn, loweredSchool, loweredFavFriend, loweredRollNo]
        );


        console.log('Security information added successfully');

        // Send response
        res.json({ success: true, message: 'Security information added successfully' });
    } catch (error) {
        console.error('Error adding security information:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// app.post('/api/addprofile', [authenticateToken, upload.single('image'), async(req, res) => {
//     let { roll_no, name, email, phone, date, sport_name } = req.body;
//     roll_no = roll_no.toLowerCase();

//     try {
//         if (!req.file) {
//             throw new Error('No photo uploaded.');
//         }

//         console.log("API addprofile requested");
//         const fileUploadResponse = await uploadFileToGoogleDrive(req.file, name);
//         const filePath = fileUploadResponse.id; // Store file ID from Google Drive

//         const updateQuery = `
//             UPDATE profile
//             SET name = ?,
//                 photo_path = ?,
//                 email = ?,
//                 phone = ?
//             WHERE roll_no = ?
//         `;

//         const [result] = await pool.execute(updateQuery, [name, filePath, email, phone, roll_no]);

//         const qaCheckQuery = `
//             SELECT * FROM qa
//             WHERE roll_no = ?
//         `;
//         const [qaRows] = await pool.execute(qaCheckQuery, [roll_no]);

//         if (qaRows.length === 0) {
//             const insertQAQuery = `
//                 INSERT INTO qa (roll_no, dob)
//                 VALUES (?, ?)
//             `;
//             await pool.execute(insertQAQuery, [roll_no, date]);
//             console.log("Data inserted into QA table");
//         }

//         console.log("Profile updated successfully");
//         res.status(200).json({ success: true, message: "Profile added/updated successfully" });
//     } catch (error) {
//         console.error("Error adding/updating profile: ", error);
//         res.status(500).json({ error: "Error adding/updating profile." });
//     }
// }]);

// API endpoint for verifying roll number and date of birth



app.post('/api/addprofile', [authenticateToken, upload.single('image'), async(req, res) => {
    let { roll_no, name, email, phone, date, sport_name } = req.body;
    roll_no = roll_no.toLowerCase();

    try {
        if (!req.file) {
            throw new Error('No photo uploaded.');
        }

        console.log("API addprofile requested");
        const fileUploadResponse = await uploadFile(req.file, name);
        const filePath = fileUploadResponse.id; // Store file ID from Google Drive

        const updateQuery = `
            UPDATE profile
            SET name = ?,
                photo_path = ?,
                email = ?,
                phone = ?
            WHERE roll_no = ?
        `;

        const [result] = await pool.execute(updateQuery, [name, filePath, email, phone, roll_no]);

        const qaCheckQuery = `
            SELECT * FROM qa
            WHERE roll_no = ?
        `;
        const [qaRows] = await pool.execute(qaCheckQuery, [roll_no]);

        if (qaRows.length === 0) {
            const insertQAQuery = `
                INSERT INTO qa (roll_no, dob)
                VALUES (?, ?)
            `;
            await pool.execute(insertQAQuery, [roll_no, date]);
            console.log("Data inserted into QA table");
        }

        console.log("Profile updated successfully");
        res.status(200).json({ success: true, message: "Profile added/updated successfully" });
    } catch (error) {
        console.error("Error adding/updating profile: ", error);
        res.status(500).json({ error: "Error adding/updating profile." });
    }
}]);



app.post('/api/verifyroleno', async(req, res) => {
    let { roll_no, dob } = req.body;

    roll_no = roll_no.toLowerCase(); // Convert roll_no to lowercase

    try {
        console.log('API verifyroleno requested');

        // Check if the user exists in the qa table with the provided roll number and DOB
        const [user] = await pool.execute('SELECT * FROM qa WHERE LOWER(roll_no) = ? AND dob = ?', [roll_no, dob]);

        if (user.length > 0) {
            // If user exists and credentials are correct, return success
            console.log('User authenticated');
            res.json({ success: true, message: 'User authenticated successfully' });
        } else {
            // If user doesn't exist or credentials are incorrect, return error
            console.log('Invalid credentials');
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error verifying credentials:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for verifying security question answer
app.post('/api/verifysecurity', async(req, res) => {
    const { roll_no, qa_id, qa_answer } = req.body;

    // Convert roll_no to lowercase
    const lowercaseRollNo = roll_no.toLowerCase();

    try {
        console.log('API verifysecurity requested');

        let columnToCheck;

        // Determine the column to check based on qa_id
        switch (qa_id) {
            case 1:
                columnToCheck = 'hospital_born';
                break;
            case 2:
                columnToCheck = 'school';
                break;
            case 3:
                columnToCheck = 'fav_friend';
                break;
            default:
                return res.status(400).json({ error: 'Invalid security question ID' });
        }

        // Fetch the correct answer from the qa table based on roll_no
        const [securityInfo] = await pool.execute(`SELECT ${columnToCheck} FROM qa WHERE LOWER(roll_no) = ?`, [lowercaseRollNo]);

        // Check if the security information exists for the provided roll_no
        if (securityInfo.length === 0) {
            return res.status(404).json({ error: 'Security information not found' });
        }

        // Extract the correct answer from the fetched security information
        const correctAnswer = securityInfo[0][columnToCheck];

        // Compare the provided answer with the correct answer
        if (correctAnswer.toLowerCase() === qa_answer.toLowerCase()) {
            // If the answers match, send success response
            return res.json({ success: true, message: 'Security question answer is correct' });
        } else {
            // If the answers don't match, send error response
            return res.status(400).json({ error: 'Security question answer is incorrect' });
        }
    } catch (error) {
        console.error('Error verifying security question answer:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for resetting password
app.post('/api/resetpassword', async(req, res) => {
    let { roll_no, new_password } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        // Log API request
        console.log('API resetpassword requested');

        // Check if the roll number exists in the login table
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = ?', [roll_no]);

        // If roll number doesn't exist, return error
        if (existingUser.length === 0) {
            return res.status(400).json({ error: 'Invalid roll number' });
        }

        // Update password for the user with provided roll number
        const updateQuery = 'UPDATE login SET password = ? WHERE LOWER(roll_no) = ?';
        await pool.execute(updateQuery, [new_password, roll_no]);

        // Send response
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        // Handle errors
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for hard resetting password
app.post('/api/hardresetpassword', [authenticateToken, async(req, res) => {
    const { roll_no } = req.body;

    try {
        console.log('API hardresetpassword requested');

        // Set password to roll_no
        const password = roll_no;

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update the password for the user with the provided roll number
        const updateQuery = 'UPDATE login SET password = ? WHERE roll_no = ?';
        const [updateResult] = await pool.execute(updateQuery, [hashedPassword, roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// API endpoint for deactivating a user
app.post('/api/deactivateuser', [authenticateToken, async(req, res) => {
    let { roll_no } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API deactivateuser requested');

        // Update is_active to 0 for the user with the provided roll number
        const updateQuery = 'UPDATE login SET is_active = 0 WHERE LOWER(roll_no) = ?';
        const [updateResult] = await pool.execute(updateQuery, [roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'User deactivated successfully' });
    } catch (error) {
        console.error('Error deactivating user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// API endpoint for deactivating a user
app.post('/api/activateuser', [authenticateToken, async(req, res) => {
    let { roll_no } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API deactivateuser requested');

        // Update is_active to 0 for the user with the provided roll number
        const updateQuery = 'UPDATE login SET is_active = 1 WHERE LOWER(roll_no) = ?';
        const [updateResult] = await pool.execute(updateQuery, [roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'User activated successfully' });
    } catch (error) {
        console.error('Error deactivating user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


app.post('/api/updateuser', async(req, res) => {
    let { roll_no, sport_id, role_id, gender, year } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();


    try {
        console.log('API updateusers requested');

        // Update profile table
        const updateProfileQuery = 'UPDATE profile SET sport_id = ?,gender = ?, year = ? WHERE LOWER(roll_no) = ?';
        const [updateProfileResult] = await pool.execute(updateProfileQuery, [sport_id, gender, year, roll_no]);

        // Check if any rows were affected by the update in profile table
        if (updateProfileResult.affectedRows === 0) {
            console.log('User not found in profile table');
            return res.status(404).json({ error: 'User not found in profile table' });
        }

        // Update login table
        const updateLoginQuery = 'UPDATE login SET role_id = ? WHERE LOWER(roll_no) = ?';
        const [updateLoginResult] = await pool.execute(updateLoginQuery, [role_id, roll_no]);

        // Check if any rows were affected by the update in login table
        if (updateLoginResult.affectedRows === 0) {
            console.log('User not found in login table');
            return res.status(404).json({ error: 'User not found in login table' });
        }

        // Send success response
        res.json({ success: true, message: 'User profile updated ' });
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for displaying roles data
app.get('/api/displayroles', [authenticateToken, async(req, res) => {
    try {
        console.log('API displayroles requested');

        // Retrieve data from the roles table
        const [rolesData] = await pool.execute('SELECT * FROM roles');

        // Send response with the retrieved roles data
        res.json({ success: true, roles: rolesData });
    } catch (error) {
        console.error('Error displaying roles data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);





// API endpoint for displaying members with role_name and sport_name
app.get('/api/displaymem', authenticateToken, async(req, res) => {
    try {
        // Query to join profile, login, roles, and sports tables
        const [rows, fields] = await pool.query(`
            SELECT 
                profile.roll_no, 
                profile.name, 
                profile.photo_path, 
                profile.email, 
                sports.sport_name AS sport_name,
                profile.year, 
                profile.phone, 
                profile.gender, 
                login.is_active, 
                login.date,
                login.role_id,
                roles.role_name AS role_name,
                login.spl_role,
                spl_role_names.role_name AS spl_role_name
            FROM 
                profile
            INNER JOIN 
                login ON profile.roll_no = login.roll_no
            LEFT JOIN
                roles ON login.role_id = roles.role_id
            LEFT JOIN
                roles AS spl_role_names ON login.spl_role = spl_role_names.role_id
            LEFT JOIN
                sports ON profile.sport_id = sports.sport_id
        `);

        res.json(rows); // Send the result as JSON response
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API endpoint for displaying members with role_name and sport_name for a specific role_no
app.post('/api/displaymem', authenticateToken, async(req, res) => {
    try {
        const { roll_no } = req.body; // Assuming role_no is passed in the request body
        console.log('API displaymember requested');
        // Query to join profile, login, roles, and sports tables filtered by roll_no
        const [rows, fields] = await pool.query(`
            SELECT 
                profile.roll_no, 
                profile.name, 
                profile.photo_path, 
                profile.email, 
                sports.sport_name AS sport_name,
                profile.year, 
                profile.phone, 
                profile.gender, 
                login.is_active, 
                login.date,
                login.role_id,
                roles.role_name AS role_name,
                login.spl_role,
                spl_role_names.role_name AS spl_role_name
            FROM 
                profile
            INNER JOIN 
                login ON profile.roll_no = login.roll_no
            LEFT JOIN
                roles ON login.role_id = roles.role_id
            LEFT JOIN
                roles AS spl_role_names ON login.spl_role = spl_role_names.role_id
            LEFT JOIN
                sports ON profile.sport_id = sports.sport_id
            WHERE 
                profile.roll_no = ?
        `, [roll_no]);

        res.json(rows); // Send the result as JSON response
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



// API endpoint for displaying filtered members
app.post('/api/displaymembersfilter', [authenticateToken, async(req, res) => {
    const { year, sport_id } = req.body;

    try {
        console.log('API displaymembersfilter requested');

        let selectQuery = 'SELECT * FROM profile';

        // Select roll_no from login table where role_id != 0
        const [rollNos] = await pool.execute('SELECT roll_no FROM login WHERE role_id != 0');

        // Check if roll numbers are retrieved
        if (rollNos.length > 0) {
            // Extract roll numbers from the result
            const rollNumbers = rollNos.map(row => row.roll_no);

            // Build the WHERE clause based on retrieved roll numbers
            selectQuery += ` WHERE roll_no IN (${rollNumbers.map(() => '?').join(', ')})`;

            // Add filter for sport_id if provided
            if (sport_id) {
                selectQuery += ' AND sport_id = ?';
            }

            // Add filter for year if provided
            if (year) {
                selectQuery += ' AND year = ?';
            }

            // Prepare filter parameters
            let filterParams = rollNumbers;
            if (sport_id && year) {
                filterParams.push(sport_id, year);
            } else if (sport_id) {
                filterParams.push(sport_id);
            } else if (year) {
                filterParams.push(year);
            }

            // Execute the query with appropriate parameters
            const [filteredMembers] = await pool.execute(selectQuery, filterParams);

            // Send response with the filtered members
            res.json({ success: true, filteredMembers });
        } else {
            // If no roll numbers are retrieved, send an empty response
            res.json({ success: true, filteredMembers: [] });
        }
    } catch (error) {
        console.error('Error displaying filtered members:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// API endpoint for updating profile year and concatenating new year with existing one
app.post('/api/nextyear', [authenticateToken, async(req, res) => {
    let { roll_no, year } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API nextyear requested');

        // Retrieve existing year for the user with the provided roll number
        const [existingYear] = await pool.execute('SELECT year FROM profile WHERE LOWER(roll_no) = ?', [roll_no]);

        let newYear;
        if (existingYear.length > 0) {
            // Concatenate new year with existing one if it exists
            newYear = existingYear[0].year ? `${existingYear[0].year},${year}` : year;

            // Update profile year for the user with the provided roll number
            const updateQuery = 'UPDATE profile SET year = ? WHERE LOWER(roll_no) = ?';
            await pool.execute(updateQuery, [newYear, roll_no]);
        } else {
            // If the user doesn't exist, return an error
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'Year updated successfully' });
    } catch (error) {
        console.error('Error updating year:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);





// API endpoint for adding an event
app.post('/api/addevent', [authenticateToken, async(req, res) => {
    let { event_name, sport_name, date, time, entry_fee, is_team, event_description, no_of_prizes, category, gender, form_link, last_date, location, roll_no, created_date } = req.body;

    // Convert event_name, event_description, location, and roll_no (created_by) to lowercase
    event_name = event_name.toLowerCase();
    event_description = event_description.toLowerCase();
    location = location.toLowerCase(); // Correct variable name to lowercase
    roll_no = roll_no.toLowerCase();

    try {

        console.log("api add event requested")
            // Query to get sport_id from sports table based on sport_name
        const getSportIdQuery = `SELECT sport_id FROM sports WHERE sport_name = ?`;
        const [rows, fields] = await pool.execute(getSportIdQuery, [sport_name]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Sport not found' });
        }

        const sport_id = rows[0].sport_id;

        // Insert new event into the event table with provided created_date
        const insertQuery = `INSERT INTO event (event_name, sport_id, event_date, event_time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place, created_by, created_date, approval_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const result = await pool.execute(insertQuery, [event_name, sport_id, date, time, entry_fee, is_team, event_description, no_of_prizes, category, gender, form_link, last_date, location, roll_no, created_date, 0]);

        // Send response
        res.json({ success: true, message: 'Event added successfully' });
    } catch (error) {
        console.error('Error adding event:', error);
        if (error.sqlMessage) {
            console.error('SQL Error:', error.sqlMessage);
        }
        res.status(500).json({ error: 'Internal Server Error' });
    }

}]);



// API endpoint for event approval
app.post('/api/eventapproval', [authenticateToken, async(req, res) => {
    const { event_id, approval_date } = req.body;

    try {
        console.log('API eventapproval requested');

        // Set approval_status to 1 and update approval_date
        const updateQuery = `UPDATE event SET approval_status = ?, approval_date = ? WHERE event_id = ?`;
        const result = await pool.execute(updateQuery, [1, approval_date, event_id]);

        // Check if any rows were affected by the update
        if (result[0].affectedRows === 0) {
            console.log('Event not found');
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response
        res.json({ success: true, message: 'Event approved' });
    } catch (error) {
        console.error('Error updating event approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// API endpoint for event approval
app.post('/api/unapproval', [authenticateToken, async(req, res) => {
    const { event_id, approval_date } = req.body;

    try {
        console.log('API event unapproval requested');

        // Set approval_status to 1 and update approval_date
        const updateQuery = `UPDATE event SET approval_status = ?, approval_date = ? WHERE event_id = ?`;
        const result = await pool.execute(updateQuery, [2, approval_date, event_id]);

        // Check if any rows were affected by the update
        if (result[0].affectedRows === 0) {
            console.log('Event not found');
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response
        res.json({ success: true, message: 'Event Declined' });
    } catch (error) {
        console.error('Error updating event approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



app.post('/api/adminaddevent', authenticateToken, async(req, res) => {
    let { event_name, sport_name, date, time, entry_fee, is_team, event_description, no_of_prizes, category, gender, form_link, last_date, location, roll_no, created_date } = req.body;

    // Convert fields to lowercase if needed
    event_name = event_name.toLowerCase();
    event_description = event_description.toLowerCase();
    location = location.toLowerCase();
    roll_no = roll_no.toLowerCase();


    try {

        console.log('Api admin add event requested');

        const insertQuery = `
            INSERT INTO event 
                (event_name, sport_id, event_date, event_time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place, created_by, created_date, approval_status, approval_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const result = await pool.execute(insertQuery, [event_name, sport_name, date, time, entry_fee, is_team, event_description, no_of_prizes, category, gender, form_link, last_date, location, roll_no, created_date, 1, created_date]);
        console.log('Event added successfully:', event_name);

        // Send response
        res.json({ success: true, message: 'Event added successfully' });
    } catch (error) {
        console.error('Error adding event:', error);
        if (error.sqlMessage) {
            console.error('SQL Error:', error.sqlMessage);
        }
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for displaying approved event
app.get('/api/displayevent', async(req, res) => {
    try {
        console.log('API displayevent requested');

        // Select event with approval_status = 1
        const selectQuery = `
        SELECT event.*, sports.sport_name 
        FROM event 
        JOIN sports ON event.sport_id = sports.sport_id 
        WHERE event.approval_status = ? 
        ORDER BY event.event_date DESC
    `;
        const [event] = await pool.execute(selectQuery, [1]);

        // Send response with the retrieved event
        res.json({ success: true, event });
    } catch (error) {
        console.error('Error displaying event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for displaying approved events by sport_name
app.post('/api/displayeventsport', async(req, res) => {
    try {
        const { sport_name } = req.body;
        console.log('API displayevent requested');



        // Select events with approval_status = 1 for the given sport_name
        const selectQuery = `
            SELECT event.*, sports.sport_name 
            FROM event 
            JOIN sports ON event.sport_id = sports.sport_id 
            WHERE event.approval_status = 1 AND sports.sport_name = ? 
            ORDER BY event.approval_date DESC
        `;

        const [event] = await pool.execute(selectQuery, [sport_name]);

        // Send response with the retrieved events
        res.json({ success: true, event });
    } catch (error) {
        console.error('Error displaying events:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



app.post('/api/displayeventfilter', authenticateToken, async(req, res) => {
    try {
        const { event_id } = req.body;
        console.log('API displayevent requested');

        // Select event with approval_status = 1 and matching event_id, joining with sports table
        const selectQuery = `
            SELECT event.*, sports.sport_name
            FROM event 
            JOIN sports ON event.sport_id = sports.sport_id
            WHERE event.approval_status = 1 AND event.event_id = ?
        `;

        const [event] = await pool.execute(selectQuery, [event_id]);

        if (event.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response with the retrieved event
        res.json({ success: true, event: event[0] });
    } catch (error) {
        console.error('Error displaying event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/api/displayeventfilternone', authenticateToken, async(req, res) => {
    try {
        const { event_id } = req.body;
        console.log('API displayevent requested');

        // Select event with approval_status = 1 and matching event_id, joining with sports table
        const selectQuery = `
            SELECT event.*, sports.sport_name
            FROM event 
            JOIN sports ON event.sport_id = sports.sport_id
            WHERE event.approval_status = 0 AND event.event_id = ?
        `;

        const [event] = await pool.execute(selectQuery, [event_id]);

        if (event.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response with the retrieved event
        res.json({ success: true, event: event[0] });
    } catch (error) {
        console.error('Error displaying event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/displayeventfilternnotapproved', authenticateToken, async(req, res) => {
    try {
        const { event_id } = req.body;
        console.log('API displayevent not approved requested');

        // Select event with approval_status = 1 and matching event_id, joining with sports table
        const selectQuery = `
            SELECT event.*, sports.sport_name
            FROM event 
            JOIN sports ON event.sport_id = sports.sport_id
            WHERE event.approval_status = 0 AND event.event_id = ?
        `;

        const [event] = await pool.execute(selectQuery, [event_id]);

        if (event.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response with the retrieved event
        res.json({ success: true, event: event[0] });
    } catch (error) {
        console.error('Error displaying event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/api/displayeventfilterall', authenticateToken, async(req, res) => {
    try {
        const { event_id } = req.body;
        console.log('API displayevent not approved requested');

        // Select event with approval_status = 1 and matching event_id, joining with sports table
        const selectQuery = `
            SELECT event.*, sports.sport_name
            FROM event 
            JOIN sports ON event.sport_id = sports.sport_id
            WHERE event.approval_status != 0 AND event.event_id = ?
        `;

        const [event] = await pool.execute(selectQuery, [event_id]);

        if (event.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response with the retrieved event
        res.json({ success: true, event: event[0] });
    } catch (error) {
        console.error('Error displaying event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint for display event an specific sport pending
app.post('/api/createdevent', [authenticateToken, async(req, res) => {
    try {
        const { sport_name } = req.body;
        console.log('API createdevent requested');

        // Step 1: Retrieve sport_id from sports table based on sport_name from request body
        const sportQuery = `
            SELECT sport_id
            FROM sports
            WHERE sport_name = ?
        `;
        const [sportResult] = await pool.execute(sportQuery, [sport_name]);
        const sport_id = sportResult[0].sport_id;

        // Step 2: Retrieve events associated with the sport_id where approval_status = 0
        const eventQuery = `
            SELECT e.*, p.roll_no, p.name, p.email, p.photo_path
            FROM event e
            JOIN profile p ON e.created_by = p.roll_no
            WHERE e.sport_id = ? AND e.approval_status = 0
            ORDER BY e.created_date DESC
        `;

        const [events] = await pool.execute(eventQuery, [sport_id]);

        // Construct response object
        const responseData = {
            success: true,
            sport_name: sport_name,
            events: events,
        };

        // Send response with all data in a single JSON object
        res.json(responseData);

    } catch (error) {
        console.error('Error retrieving created event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// API endpoint for display event an specific sport
app.post('/api/createdeventhist', [authenticateToken, async(req, res) => {
    try {
        const { sport_name } = req.body;
        console.log('API createdeventhist requested');

        // Step 1: Retrieve sport_id from sports table based on sport_name from request body
        const sportQuery = `
            SELECT sport_id
            FROM sports
            WHERE sport_name = ?
        `;
        const [sportResult] = await pool.execute(sportQuery, [sport_name]);
        const sport_id = sportResult[0].sport_id;

        // Step 2: Retrieve historical events associated with the sport_id where approval_status != 0
        const eventQuery = `
            SELECT e.*, p.roll_no, p.name, p.email, p.photo_path
            FROM event e
            JOIN profile p ON e.created_by = p.roll_no
            WHERE e.sport_id = ? AND e.approval_status != 0
            ORDER BY e.approval_date DESC
        `;

        const [events] = await pool.execute(eventQuery, [sport_id]);

        // Construct response object
        const responseData = {
            success: true,
            sport_name: sport_name,
            events: events,
        };

        // Send response with all data in a single JSON object
        res.json(responseData);

    } catch (error) {
        console.error('Error retrieving created event history:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// API endpoint for shhowing pending event
app.get('/api/showingevents', authenticateToken, async(req, res) => {
    try {
        console.log('API showingevents requested');

        // Step 1: Retrieve events with approval_status = 0 and join with profile table
        const eventQuery = `
            SELECT e.*, p.roll_no, p.name AS profile_name, p.email, p.photo_path, s.sport_name
            FROM event e
            JOIN profile p ON e.created_by = p.roll_no
            JOIN sports s ON e.sport_id = s.sport_id
            WHERE e.approval_status = 0
               ORDER BY e.created_date DESC
        `;

        const [events] = await pool.execute(eventQuery);

        // Step 2: Construct response object
        const responseData = {
            success: true,
            events: events,
        };

        // Step 3: Send response with all data in a single JSON object
        res.json(responseData);

    } catch (error) {
        console.error('Error retrieving showing events:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint for showing all events to admin
app.get('/api/showingeventhist', authenticateToken, async(req, res) => {
    try {
        console.log('API showingevents requested');

        // Step 1: Retrieve events with approval_status = 0 and join with profile table
        const eventQuery = `
            SELECT e.*, p.roll_no, p.name AS profile_name, p.email, p.photo_path, s.sport_name
            FROM event e
            JOIN profile p ON e.created_by = p.roll_no
            JOIN sports s ON e.sport_id = s.sport_id
            WHERE e.approval_status != 0
              ORDER BY e.approval_date DESC
        `;

        const [events] = await pool.execute(eventQuery);

        // Step 2: Construct response object
        const responseData = {
            success: true,
            events: events,
        };

        // Step 3: Send response with all data in a single JSON object
        res.json(responseData);

    } catch (error) {
        console.error('Error retrieving showing events:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint for updating an event by admin
app.post('/api/updateevent', authenticateToken, async(req, res) => {
    const { event_id, event_name, sport_name, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, place } = req.body;

    try {
        console.log('API adminupdateevent requested');
        console.log('Request Body:', req.body);

        // Retrieve sport_id from sports table based on sport_name
        const selectSportQuery = 'SELECT sport_id FROM sports WHERE sport_name = ?';
        const [sportResult] = await pool.execute(selectSportQuery, [sport_name]);

        if (sportResult.length === 0) {
            return res.status(404).json({ error: 'Sport not found' });
        }

        const sport_id = sportResult[0].sport_id;

        // Update the event in the database
        const updateQuery = `
            UPDATE event 
            SET 
                event_name = ?, 
                sport_id = ?, 
                event_date = ?, 
                event_time = ?, 
                entry_fee = ?, 
                is_team = ?, 
                event_description = ?, 
                no_of_prize = ?, 
                category = ?, 
                gender = ?, 
                form_link = ?, 
                place = ? 
            WHERE 
                event_id = ?`;

        await pool.execute(updateQuery, [
            event_name,
            sport_id,
            date,
            time,
            entry_fee,
            is_team,
            event_description,
            no_of_prize,
            category,
            gender,
            form_link,
            place,
            event_id
        ]);

        // Send success response
        res.json({ success: true, message: 'Event updated successfully' });
    } catch (error) {
        console.error('Error updating event by admin:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for updating an event by admin
// app.post('/api/adminupdateevent', [authenticateToken, async(req, res) => {
//     const { event_id, event_name, sport_name, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, place } = req.body;

//     try {
//         console.log('API adminupdateevent requested');
//         console.log('Request Body:', req.body);
//         // Update the event in the database
//         const updateQuery = `
//             UPDATE event 
//             SET 
//                 event_name = ?, 
//                 sport_id = ?, 
//                 date = ?, 
//                 time = ?, 
//                 entry_fee = ?, 
//                 is_team = ?, 
//                 event_description = ?, 
//                 no_of_prize = ?, 
//                 category = ?, 
//                 gender = ?, 
//                 form_link = ?, 
//                 place = ? 
//             WHERE 
//                 event_id = ?`;

//         await pool.execute(updateQuery, [
//             event_name,
//             sport_id,
//             date,
//             time,
//             entry_fee,
//             is_team,
//             event_description,
//             no_of_prize,
//             category,
//             gender,
//             form_link,
//             place,
//             event_id
//         ]);

//         // Send success response
//         res.json({ success: true, message: 'Event updated successfully' });
//     } catch (error) {
//         console.error('Error updating event by admin:', error);
//         res.status(500).json({ error: 'Internal Server Error' });
//     }
// }]);



// Add Blog
app.post('/api/addblog', [authenticateToken, async(req, res) => {
    let { title, img_path, description, creation_date, approval_date, created_by } = req.body;

    // Convert necessary fields to lowercase
    title = title.toLowerCase();
    description = description.toLowerCase();
    created_by = created_by.toLowerCase();

    try {
        console.log('API addblog requested');

        // Insert new blog into the blog table with provided creation_date and approval_date
        const insertQuery = `INSERT INTO blog (title, img_path, description, creation_date, approval_date, created_by, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        await pool.execute(insertQuery, [title, img_path, description, creation_date, approval_date, created_by, 0]);

        res.json({ success: true, message: 'Blog added successfully' });
    } catch (error) {
        console.error('Error adding blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Blog Approval
app.post('/api/blogapproval', [authenticateToken, async(req, res) => {
    const { blog_id, approval_date } = req.body;

    try {
        console.log('API blogapproval requested');

        // Set is_approved to 1 and update approval_date
        const updateQuery = `UPDATE blog SET is_approved = ?, approval_date = ? WHERE blog_id = ?`;
        const result = await pool.execute(updateQuery, [1, approval_date, blog_id]);

        if (result[0].affectedRows === 0) {
            console.log('Blog not found');
            return res.status(404).json({ error: 'Blog not found' });
        }

        res.json({ success: true, message: 'Blog approval status updated successfully' });
    } catch (error) {
        console.error('Error updating blog approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Admin Add Blog
app.post('/api/adminaddblog', [authenticateToken, async(req, res) => {
    const { title, img_path, description, created_by, creation_date, approval_date } = req.body;

    try {
        console.log('API adminaddblog requested');

        // Insert new blog into the blog table with is_approved = 1
        const insertQuery = `INSERT INTO blog (title, img_path, description, creation_date, approval_date, created_by, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        await pool.execute(insertQuery, [title.toLowerCase(), img_path, description.toLowerCase(), creation_date, approval_date, created_by.toLowerCase(), 1]);

        res.json({ success: true, message: 'Blog added successfully' });
    } catch (error) {
        console.error('Error adding blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Display Approved Blogs
app.get('/api/displayblogs', [authenticateToken, async(req, res) => {
    try {
        console.log('API displayblogs requested');

        const selectQuery = 'SELECT * FROM blog WHERE is_approved = ?';
        const [blogs] = await pool.execute(selectQuery, [1]);

        res.json({ success: true, blogs });
    } catch (error) {
        console.error('Error displaying blogs:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Retrieve Created Blogs by Roll Number
app.post('/api/createdblogs', [authenticateToken, async(req, res) => {
    const { roll_no } = req.body;
    const rollNoLower = roll_no.toLowerCase();

    try {
        console.log('API createdblogs requested');

        // Retrieve blogs created by the specified roll number
        const selectQuery = 'SELECT * FROM blog WHERE created_by = ?';
        const [createdBlogs] = await pool.execute(selectQuery, [rollNoLower]);

        res.json({ success: true, createdBlogs });
    } catch (error) {
        console.error('Error retrieving created blogs:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


app.post('/api/updateblog', [authenticateToken, async(req, res) => {
    const { blog_id, title, img_path, description, creation_date, approval_date } = req.body;

    try {
        console.log('API updateblog requested');

        // Check if the blog exists and its current is_approved status
        const [blogRows] = await pool.execute('SELECT is_approved FROM blog WHERE blog_id = ?', [blog_id]);

        if (blogRows.length === 0) {
            return res.status(404).json({ error: 'Blog not found' });
        }

        const isApproved = blogRows[0].is_approved;

        // Check if the blog is already approved
        if (isApproved === 1) {
            return res.status(403).json({ error: 'Blog is already published and cannot be edited' });
        }

        // Update the blog
        const updateQuery = `
            UPDATE blog 
            SET 
                title = ?, 
                img_path = ?, 
                description = ?, 
                creation_date = ?, 
                approval_date = ? 
            WHERE 
                blog_id = ?`;

        await pool.execute(updateQuery, [
            title,
            img_path,
            description,
            creation_date,
            approval_date,
            blog_id
        ]);

        res.json({ success: true, message: 'Blog updated successfully' });
    } catch (error) {
        console.error('Error updating blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// Admin Update Blog
app.post('/api/adminupdateblog', [authenticateToken, async(req, res) => {
    const { blog_id, title, img_path, description, creation_date, approval_date } = req.body;

    try {
        console.log('API adminupdateblog requested');

        const updateQuery = `
            UPDATE blog 
            SET 
                title = ?, 
                img_path = ?, 
                description = ?, 
                creation_date = ?, 
                approval_date = ? 
            WHERE 
                blog_id = ?`;

        await pool.execute(updateQuery, [
            title,
            img_path,
            description,
            creation_date,
            approval_date,
            blog_id
        ]);

        res.json({ success: true, message: 'Blog updated successfully' });
    } catch (error) {
        console.error('Error updating blog by admin:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




//add achievement


app.post('/api/addachievement', [authenticateToken, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async(req, res) => {
    let { description, achievement_name, name, achievement_date, roll_no, is_team } = req.body;

    // Convert necessary fields to lowercase
    name = name.toLowerCase();
    description = description.toLowerCase();

    // Handle roll_no parsing gracefully
    let parsedRollNo;
    try {
        parsedRollNo = JSON.parse(roll_no); // Attempt to parse roll_no
        if (!Array.isArray(parsedRollNo)) {
            throw new Error('roll_no is not an array');
        }
        // Convert each item to lowercase
        parsedRollNo = parsedRollNo.map(r => r.toLowerCase());
    } catch (error) {
        return res.status(400).json({ error: 'Invalid roll_no format' });
    }

    // Set location to null
    const location = null;

    try {
        // Upload files to Google Drive and get their IDs
        const imageFileId = req.files && req.files['image'] ? await uploadFile(req.files['image'][0], name) : null;
        const pdfFileId = req.files && req.files['pdf'] ? await uploadFile(req.files['pdf'][0], name) : null;

        // Insert new achievement into the achievement table
        const insertQuery = `
            INSERT INTO achievement 
            (description, achievement_name, name, achievement_date, roll_no, location, photo_path, certificate_path, is_team, is_inside_campus, is_display) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        await pool.execute(insertQuery, [
            description, achievement_name, name, achievement_date, JSON.stringify(parsedRollNo), location, imageFileId, pdfFileId, is_team, 0, 0
        ]);

        res.json({ success: true, message: 'Achievement added successfully' });
    } catch (error) {
        console.error('Error adding achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// app.post('/api/addachievement', [authenticateToken, upload1.fields([{ name: 'image', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async(req, res) => {
//     let { description, achievement_name, name, achievement_date, roll_no, is_team } = req.body;

//     // Convert necessary fields to lowercase
//     name = name.toLowerCase();
//     description = description.toLowerCase();



//     // Handle roll_no parsing gracefully
//     let parsedRollNo;
//     try {
//         parsedRollNo = JSON.parse(roll_no); // Attempt to parse roll_no
//         if (!Array.isArray(parsedRollNo)) {
//             throw new Error('roll_no is not an array');
//         }
//         // Convert each item to lowercase
//         parsedRollNo = parsedRollNo.map(r => r.toLowerCase());

//     } catch (error) {

//         return res.status(400).json({ error: 'Invalid roll_no format' });
//     }

//     // Set location to null
//     const location = null;

//     try {


//         // Extract uploaded file paths
//         const photo_path = req.files && req.files['image'] ? req.files['image'][0].path : null; // Image path
//         const certificate_path = req.files && req.files['pdf'] ? req.files['pdf'][0].path : null; // PDF path


//         // Insert new achievement into the achievement table
//         const insertQuery = `
//             INSERT INTO achievement 
//             (description, achievement_name, name, achievement_date, roll_no, location, photo_path, certificate_path, is_team, is_inside_campus, is_display) 
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;



//         await pool.execute(insertQuery, [
//             description, achievement_name, name, achievement_date, JSON.stringify(parsedRollNo), location, photo_path, certificate_path, is_team, 0, 0
//         ]);


//         res.json({ success: true, message: 'Achievement added successfully' });
//     } catch (error) {

//         res.status(500).json({ error: 'Internal Server Error' });
//     }
// }]);

// Achievement Approval


app.post('/api/achievementapproval', [authenticateToken, async(req, res) => {
    const { achievement_id } = req.body;

    try {
        console.log('API achievementapproval requested');

        // Set is_display to 1
        const updateQuery = `UPDATE achievement SET is_display = ? WHERE achievement_id = ?`;
        const result = await pool.execute(updateQuery, [1, achievement_id]);

        if (result[0].affectedRows === 0) {
            console.log('Achievement not found');
            return res.status(404).json({ error: 'Achievement not found' });
        }

        res.json({ success: true, message: 'Achievement approval status updated successfully' });
    } catch (error) {
        console.error('Error updating achievement approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




// Admin Add Achievement without Token Authentication


app.post('/api/adminaddachievement', upload.fields([{ name: 'image', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async(req, res) => {
    let { description, achievement_name, name, achievement_date, roll_no, is_team, sport_id } = req.body;
    console.log('API adminaddachievement requested');
    console.log('Request Body:', req.body);

    // Convert necessary fields to lowercase
    name = name.toLowerCase();
    description = description.toLowerCase();

    // Handle roll_no parsing gracefully
    let parsedRollNo;
    try {
        parsedRollNo = JSON.parse(roll_no); // Attempt to parse roll_no
        if (!Array.isArray(parsedRollNo)) {
            throw new Error('roll_no is not an array');
        }
        // Convert each item to lowercase
        parsedRollNo = parsedRollNo.map(r => r.toLowerCase());
    } catch (error) {
        return res.status(400).json({ error: 'Invalid roll_no format' });
    }

    // Set location to null
    const location = null;

    try {
        // Upload files to Google Drive and get their IDs
        const imageFileId = req.files && req.files['image'] ? await uploadFile(req.files['image'][0], name) : null;
        const pdfFileId = req.files && req.files['pdf'] ? await uploadFile(req.files['pdf'][0], name) : null;

        // Insert new achievement into the achievement table
        const insertQuery = `
            INSERT INTO achievement 
            (description, achievement_name, name, achievement_date, roll_no, location, photo_path, certificate_path, is_team, is_inside_campus, is_display, sport_id) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        await pool.execute(insertQuery, [
            description, achievement_name, name, achievement_date, JSON.stringify(parsedRollNo), location, imageFileId, pdfFileId, is_team, 0, 1, sport_id
        ]);

        res.json({ success: true, message: 'Achievement added successfully' });
    } catch (error) {
        console.error('Error adding achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// app.post('/api/adminaddachievement', upload1.fields([{ name: 'image', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async(req, res) => {
//     let { description, achievement_name, name, achievement_date, roll_no, is_team, sport_id } = req.body;
//     console.log('API adminaddachievement requested');
//     console.log('Request Body:', req.body);
//     // Convert necessary fields to lowercase
//     name = name.toLowerCase();
//     description = description.toLowerCase();



//     // Handle roll_no parsing gracefully
//     let parsedRollNo;
//     try {
//         parsedRollNo = JSON.parse(roll_no); // Attempt to parse roll_no
//         if (!Array.isArray(parsedRollNo)) {
//             throw new Error('roll_no is not an array');
//         }
//         // Convert each item to lowercase
//         parsedRollNo = parsedRollNo.map(r => r.toLowerCase());

//     } catch (error) {

//         return res.status(400).json({ error: 'Invalid roll_no format' });
//     }

//     // Set location to null
//     const location = null;

//     try {


//         // Extract uploaded file paths
//         const photo_path = req.files && req.files['image'] ? req.files['image'][0].path : null; // Image path
//         const certificate_path = req.files && req.files['pdf'] ? req.files['pdf'][0].path : null; // PDF path



//         // Insert new achievement into the achievement table
//         const insertQuery = `
//             INSERT INTO achievement 
//             (description, achievement_name, name, achievement_date, roll_no, location, photo_path, certificate_path, is_team, is_inside_campus, is_display,sport_id) 
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)`;



//         await pool.execute(insertQuery, [
//             description, achievement_name, name, achievement_date, JSON.stringify(parsedRollNo), location, photo_path, certificate_path, is_team, 0, 1, sport_id
//         ]);


//         res.json({ success: true, message: 'Achievement added successfully' });
//     } catch (error) {

//         res.status(500).json({ error: 'Internal Server Error' });
//     }
// });



// Admin edit achievement without Token Authentication



app.post('/api/updateachievement', upload.fields([{ name: 'image', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async(req, res) => {
    console.log('Middleware passed, entering route handler');
    let { id, description, achievement_name, name, achievement_date, roll_no, is_team, sport_id } = req.body;
    console.log('API updateachievement requested');
    console.log('Request Body:', req.body);

    // Convert necessary fields to lowercase
    name = name.toLowerCase();
    description = description.toLowerCase();

    // Handle roll_no parsing gracefully
    let parsedRollNo;
    try {
        parsedRollNo = JSON.parse(roll_no); // Attempt to parse roll_no
        if (!Array.isArray(parsedRollNo)) {
            throw new Error('roll_no is not an array');
        }
        // Convert each item to lowercase
        parsedRollNo = parsedRollNo.map(r => r.toLowerCase());
    } catch (error) {
        return res.status(400).json({ error: 'Invalid roll_no format' });
    }

    try {
        // Upload files to Google Drive and get their IDs
        const imageFileId = req.files && req.files['image'] ? await uploadFile(req.files['image'][0], name) : null;
        const pdfFileId = req.files && req.files['pdf'] ? await uploadFile(req.files['pdf'][0], name) : null;

        // Update existing achievement in the achievement table based on ID
        const updateQuery = `
            UPDATE achievement 
            SET 
                description = ?, 
                achievement_name = ?, 
                name = ?, 
                achievement_date = ?, 
                roll_no = ?, 
                photo_path = COALESCE(?, photo_path), 
                certificate_path = COALESCE(?, certificate_path), 
                is_team = ?, 
                sport_id = ?
            WHERE achievement_id = ?`;

        await pool.execute(updateQuery, [
            description, achievement_name, name, achievement_date, JSON.stringify(parsedRollNo), imageFileId, pdfFileId, is_team, sport_id, id
        ]);

        res.json({ success: true, message: 'Achievement updated successfully' });
    } catch (error) {
        console.error('Error updating achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/admindeactivateachievement', async(req, res) => {
    const { achievement_id } = req.body;
    console.log('API admindeactivateachievement requested');

    try {
        // Update the achievement to set is_display to 0
        const updateQuery = 'UPDATE achievement SET is_display = ? WHERE achievement_id = ?';
        await pool.execute(updateQuery, [0, achievement_id]);

        res.json({ success: true, message: 'Achievement deactivated successfully' });
    } catch (error) {
        console.error('Error deactivating achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/adminactivateachievement', async(req, res) => {
    const { achievement_id } = req.body;
    console.log('API adminactivateachievement requested');

    try {
        // Update the achievement to set is_display to 1 (or whatever value signifies active)
        const updateQuery = 'UPDATE achievement SET is_display = ? WHERE achievement_id = ?';
        await pool.execute(updateQuery, [1, achievement_id]);

        res.json({ success: true, message: 'Achievement activated successfully' });
    } catch (error) {
        console.error('Error activating achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/api/displayachievements', async(req, res) => {
    try {
        console.log('API displayachievements requested');

        // Modify the query to join with the sports table and select the sport_name
        const selectQuery = `
            SELECT a.*, s.sport_name 
            FROM achievement a
            LEFT JOIN sports s ON a.sport_id = s.sport_id
            WHERE a.is_display = ?`;

        const [achievements] = await pool.execute(selectQuery, [1]);

        res.json({ success: true, achievements });
    } catch (error) {
        console.error('Error displaying achievements:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

//display pending achievements
app.get('/api/displayachievementspending', async(req, res) => {
    try {
        console.log('API displayachievements requested');

        const selectQuery = `
            SELECT a.*, s.sport_name 
            FROM achievement a
            LEFT JOIN sports s ON a.sport_id = s.sport_id
            WHERE a.is_display = ?`;
        const [achievements] = await pool.execute(selectQuery, [0]);
        console.log(achievements);

        res.json({ success: true, achievements });
    } catch (error) {
        console.error('Error displaying achievements:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Retrieve Created Achievements by Roll Number
app.post('/api/createdachievements', [authenticateToken, async(req, res) => {
    const { roll_no } = req.body;
    const rollNoLower = roll_no.toLowerCase();

    try {
        console.log('API createdachievements requested');

        // Retrieve achievements created by the specified roll number
        const selectQuery = 'SELECT * FROM achievement WHERE roll_no = ?';
        const [createdAchievements] = await pool.execute(selectQuery, [rollNoLower]);

        res.json({ success: true, createdAchievements });
    } catch (error) {
        console.error('Error retrieving created achievements:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// API route for showing election years
app.get('/api/electionyear', [authenticateToken, async(req, res) => {
    try {
        console.log('API election next year data requested');

        // Fetch all election years from the database
        const query = 'SELECT * FROM election';
        const [rows] = await pool.execute(query);

        // Check if there are any results
        if (rows.length === 0) {
            return res.status(404).json({ message: 'No election years found' });
        }

        // Send the retrieved election years as the response
        res.json({ success: true, data: rows });
    } catch (error) {
        console.error('Error fetching election year data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// API route for adding 1 year
app.post('/api/electionaddyear', [authenticateToken, async(req, res) => {
    try {
        console.log('API election year data requested');

        // Extract nextyear from the request body
        const { nextyear } = req.body;

        // Check if nextyear is provided and is 1
        if (nextyear === 1) {
            // Fetch the maximum year from the database
            const maxYearQuery = 'SELECT MAX(year) AS maxYear FROM election';
            const [maxYearResult] = await pool.execute(maxYearQuery);

            // Extract the maximum year from the result
            const maxYear = maxYearResult[0].maxYear;

            // Calculate the new year to be added
            const newYear = maxYear ? maxYear + 1 : new Date().getFullYear(); // Default to current year if no years exist

            // Check if the current year is already complete (is_vote == 2)
            const checkIsVoteQuery = 'SELECT is_vote FROM election WHERE year = ?';
            const [checkIsVoteResult] = await pool.execute(checkIsVoteQuery, [maxYear]);

            if (checkIsVoteResult.length > 0 && checkIsVoteResult[0].is_vote === 2) {
                // Insert new election year with is_register = 0 and is_vote = 0
                const insertQuery = 'INSERT INTO election (year, is_register, is_vote) VALUES (?, 0, 0)';
                const [insertResult] = await pool.execute(insertQuery, [newYear]);

                // Retrieve the auto-generated election_id from the insert result
                const election_id = insertResult.insertId;

                // Send a response indicating success
                res.json({ success: true, election_id, year: newYear, message: 'New election year added' });
            } else {
                // Send an error response indicating that the current year is not complete
                res.status(400).json({ error: 'Current election year results are not finalized. Cannot add a new year yet.' });
            }
        }
    } catch (error) {
        console.error('Error fetching or adding election year data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// API route for creating an election and inserting a new election year
app.post('/api/electioncreate', [authenticateToken, async(req, res) => {
    const { year } = req.body;

    try {
        console.log('API electioncreate requested');

        // Check if the election year already exists
        const checkQuery = 'SELECT * FROM election WHERE year = ?';
        const [existingRows] = await pool.execute(checkQuery, [year]);

        if (existingRows.length > 0) {
            return res.status(400).json({ error: 'Election year already exists' });
        }

        // Insert new election year with is_register = 0 and is_vote = 0
        const insertQuery = 'INSERT INTO election (year, is_register, is_vote) VALUES (?, 0, 0)';
        const [insertResult] = await pool.execute(insertQuery, [year]);

        // Retrieve the auto-generated election_id from the insert result
        const election_id = insertResult.insertId;

        res.json({ success: true, election_id, message: 'New election year inserted successfully' });
    } catch (error) {
        console.error('Error creating election year:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


app.post('/api/votestatus', [authenticateToken, async(req, res) => {
    const { year } = req.body; // Get year from request body

    if (!year) {
        return res.status(400).json({ error: 'Year is required' });
    }

    try {


        const query = 'SELECT * FROM election WHERE year = ?';
        const [rows] = await pool.execute(query, [year]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election year not found' });
        }

        res.json({ success: true, data: rows[0] });
    } catch (error) {
        console.error('Error fetching election status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




app.post('/api/electionregisterstatus', [authenticateToken, async(req, res) => {
    const { year, status } = req.body;

    try {
        console.log('API electionregister status requested');

        // Check if the election exists and get the current registration and voting status
        const checkQuery = 'SELECT is_register, is_vote FROM election WHERE year = ?';
        const [rows] = await pool.execute(checkQuery, [year]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_register: currentRegisterStatus, is_vote: currentVoteStatus } = rows[0];

        // Check if the current registration status is 2 (election results published)
        if (currentRegisterStatus === 2) {
            return res.status(400).json({ error: 'The election results have been published. Registration status cannot be changed.' });
        }

        // Check if the status value is either 0 or 1
        if (status !== 0 && status !== 1) {
            return res.status(400).json({ error: 'Invalid status value. It should be 0 or 1.' });
        }

        // Check if trying to open registration when voting is already open
        if (status === 1 && currentVoteStatus === 1) {
            return res.status(400).json({ error: 'Cannot open registration because voting is already open.' });
        }

        // Check if trying to open registration when another year already has registration open
        if (status === 1) {
            const checkOtherRegisterQuery = 'SELECT year FROM election WHERE is_register = 1 AND year <> ?';
            const [otherRegisterRows] = await pool.execute(checkOtherRegisterQuery, [year]);

            if (otherRegisterRows.length > 0) {
                const conflictingYear = otherRegisterRows[0].year;
                return res.status(400).json({ error: `Registration for ${conflictingYear} is already open.` });
            }
        }

        // Check if another year has voting open
        const checkOtherVoteQuery = 'SELECT year FROM election WHERE is_vote = 1 AND year <> ?';
        const [otherVoteRows] = await pool.execute(checkOtherVoteQuery, [year]);

        if (otherVoteRows.length > 0) {
            const conflictingVoteYear = otherVoteRows[0].year;
            return res.status(400).json({ error: `Voting for ${conflictingVoteYear} is already open. Cannot change registration status.` });
        }

        // Update election registration status based on the provided status value
        const updateQuery = 'UPDATE election SET is_register = ? WHERE year = ?';
        await pool.execute(updateQuery, [status, year]);

        // Return appropriate success message
        const message = status === 1 ? 'Registration opened successfully' : 'Registration closed successfully';
        res.json({ success: true, message });

    } catch (error) {
        console.error('Error updating registration for election:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




app.post('/api/electionvotestatus', [authenticateToken, async(req, res) => {
    const { year, status } = req.body;

    try {
        console.log('API electionvotestatus requested');

        // Check if the election exists and get the current registration and voting status
        const checkQuery = 'SELECT is_register, is_vote FROM election WHERE year = ?';
        const [rows] = await pool.execute(checkQuery, [year]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_register: currentRegisterStatus, is_vote: currentVoteStatus } = rows[0];

        // Check if the current voting status is 2 (election results published)
        if (currentVoteStatus === 2) {
            return res.status(400).json({ error: 'The election results have been published. Voting status cannot be changed.' });
        }

        // Check if the status value is either 0 or 1
        if (status !== 0 && status !== 1) {
            return res.status(400).json({ error: 'Invalid status value. It should be 0 or 1.' });
        }

        // Check if trying to open voting when registration is open
        if (status === 1 && currentRegisterStatus === 1) {
            return res.status(400).json({ error: 'Cannot open voting because registration is already open.' });
        }



        // Check if trying to open voting when it is open for another year
        if (status === 1) {
            const checkOtherVoteQuery = 'SELECT year FROM election WHERE is_vote = 1 AND year <> ?';
            const [otherVoteRows] = await pool.execute(checkOtherVoteQuery, [year]);

            if (otherVoteRows.length > 0) {
                const conflictingVoteYear = otherVoteRows[0].year;
                return res.status(400).json({ error: `Voting for ${conflictingVoteYear} is already open.` });
            }
        }

        // Check if another year has registration open
        const checkOtherRegisterQuery = 'SELECT year FROM election WHERE is_register = 1 AND year <> ?';
        const [otherRegisterRows] = await pool.execute(checkOtherRegisterQuery, [year]);

        if (otherRegisterRows.length > 0) {
            const conflictingRegisterYear = otherRegisterRows[0].year;
            return res.status(400).json({ error: `Registration for ${conflictingRegisterYear} is already open. Cannot change voting status.` });
        }

        // Update election voting status based on the provided status value
        const updateQuery = 'UPDATE election SET is_vote = ? WHERE year = ?';
        await pool.execute(updateQuery, [status, year]);

        // Return appropriate success message
        const message = status === 1 ? 'Voting opened successfully' : 'Voting closed successfully';
        res.json({ success: true, message });

    } catch (error) {
        console.error('Error updating voting status for election:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


app.post('/api/electionroleppl', [authenticateToken, async(req, res) => {
    const { year } = req.body;


    try {
        console.log('API electionroleppl requested');

        // Fetch election data based on year
        const fetchElectionQuery = 'SELECT * FROM election WHERE year = ?';
        const [electionRows] = await pool.execute(fetchElectionQuery, [year]);

        // Check if election data exists for the given year
        if (electionRows.length === 0) {
            return res.status(404).json({ error: 'Election not found for the given year' });
        }

        const { election_id, is_reg, is_vote } = electionRows[0];

        // Determine election status based on is_vote and is_reg
        let votestatus = 0; // Default to 0

        if (is_vote === 1) {
            votestatus = 1; // Set votestatus to 1 if is_vote is 1
        } else if (is_vote === 0) {
            votestatus = 0; // Set votestatus to 2 if is_reg is 2
        } else if (is_vote === 2) {
            votestatus = 2;
        }

        // Fetch candidate data based on election_id
        const fetchCandidateQuery = 'SELECT * FROM candidate WHERE election_id = ?';
        const [candidateRows] = await pool.execute(fetchCandidateQuery, [election_id]);

        // Separate candidates into boys and girls arrays based on gender
        const boys = [];
        const girls = [];

        // Fetch profile data for each candidate
        for (let candidate of candidateRows) {
            const fetchProfileQuery = 'SELECT * FROM profile WHERE roll_no = ?';
            const [profileRows] = await pool.execute(fetchProfileQuery, [candidate.reg_roll_no]);

            if (profileRows.length > 0) {
                const profileData = profileRows[0];
                if (candidate.gender === 'Boys') {
                    boys.push({...candidate, profile: profileData });
                } else if (candidate.gender === 'Girls') {
                    girls.push({...candidate, profile: profileData });
                }
            }
        }

        // Return arrays with gender-specific candidates including profile data and election status
        res.json({ success: true, boys, girls, votestatus });

    } catch (error) {
        console.error('Error fetching election role people:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// API route for checking candidate registration status and election publish status
app.post('/api/publishcheck', [authenticateToken, async(req, res) => {
    try {
        console.log('API publish check requested');

        // Extract year from the request body
        const { year } = req.body;

        // Query to check if election is published (is_vote = 2 and is_register = 2)
        const publishStatusQuery = 'SELECT is_vote, is_register FROM election WHERE year = ?';
        const [publishStatusResult] = await pool.execute(publishStatusQuery, [year]);

        // Check if there is no election found for the provided year
        if (publishStatusResult.length === 0) {
            return res.status(404).json({ error: 'No election found for the provided year' });
        }

        const { is_vote, is_register } = publishStatusResult[0];

        // If election is already published (is_vote = 2 and is_register = 2)
        if (is_vote === 2 && is_register === 2) {
            return res.json({ message: 'Election result already published' });
        }

        // Query to fetch candidate counts by role and gender
        const candidateCheckQuery = `
            SELECT
                roles.role_id,
                roles.role_name,
                genders.gender,
                COALESCE(c.candidate_count, 0) AS candidate_count
            FROM
                (SELECT 'Boys' AS gender UNION SELECT 'Girls') AS genders
                CROSS JOIN roles
                LEFT JOIN (
                    SELECT
                        role_id,
                        gender,
                        COUNT(*) AS candidate_count
                    FROM
                        candidate
                    WHERE
                        election_id IN (SELECT election_id FROM election WHERE year = ?)
                    GROUP BY
                        role_id,
                        gender
                ) AS c ON roles.role_id = c.role_id AND genders.gender = c.gender
        `;

        // Execute the query
        const [candidateCheckResult] = await pool.execute(candidateCheckQuery, [year]);

        // Prepare response data
        const categoryStatus = [];

        // Map query results to categoryStatus
        candidateCheckResult.forEach(row => {
            categoryStatus.push({
                role_id: row.role_id, // Include role_id for filtering
                role_name: row.role_name,
                gender: row.gender,
                registered: row.candidate_count > 0
            });
        });

        // Separate into exits and missing categories
        const exits = categoryStatus.filter(status => status.registered);
        const missing = categoryStatus.filter(status => !status.registered && ![0, 5, 6].includes(status.role_id));

        // Determine the check status
        const check = missing.length === 0 ? 1 : 0;

        // Prepare the response message
        let message = '';
        if (missing.length === 0) {
            message = 'All categories have registered candidates.';
        } else {
            message = 'Categories without candidates:';
        }

        // Send the response with check status included
        res.json({ message, exits, missing, check });

    } catch (error) {
        console.error('Error checking publish status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




app.post('/api/electionregister', [authenticateToken, async(req, res) => {
    const { year, roll_no, role_id } = req.body;

    try {
        console.log('API electionregister requested');

        // Fetch election_id based on year
        const fetchElectionIdQuery = 'SELECT election_id FROM election WHERE year = ?';
        const [electionRows] = await pool.execute(fetchElectionIdQuery, [year]);

        // Check if election exists for the given year
        if (electionRows.length === 0) {
            return res.status(404).json({ error: 'Election not found for the given year' });
        }

        const election_id = electionRows[0].election_id;

        // Check if roll_no already registered for this election_id
        const fetchCandidateQuery = 'SELECT candidate_id FROM candidate WHERE election_id = ? AND reg_roll_no = ?';
        const [candidateRows] = await pool.execute(fetchCandidateQuery, [election_id, roll_no]);

        if (candidateRows.length > 0) {
            return res.status(400).json({ error: 'You are already registered for this election' });
        }

        // Fetch profile data based on roll_no
        const fetchProfileQuery = 'SELECT gender FROM profile WHERE roll_no = ?';
        const [profileRows] = await pool.execute(fetchProfileQuery, [roll_no]);

        // Check if profile data exists for the given roll_no
        if (profileRows.length === 0) {
            return res.status(404).json({ error: 'Profile not found for the given roll number' });
        }

        const gender = profileRows[0].gender;

        // Insert candidate data into candidate table
        const insertCandidateQuery = 'INSERT INTO candidate (election_id, reg_roll_no, role_id, gender) VALUES (?, ?, ?, ?)';
        await pool.execute(insertCandidateQuery, [election_id, roll_no, role_id, gender]);

        // Return success message
        res.json({ success: true, message: 'Registration successful' });

    } catch (error) {
        console.error('Error registering candidate:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


app.post('/api/electionstatus', [authenticateToken, async(req, res) => {
    const { year } = req.body; // Get year from request body
    if (!year) {
        return res.status(400).json({ error: 'Year is required' });
    }
    try {
        const query = 'SELECT * FROM election WHERE year = ?';
        const [rows] = await pool.execute(query, [year]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election year not found' });
        }
        res.json({ success: true, data: rows[0] });
    } catch (error) {
        console.error('Error fetching election status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

app.get('/api/electionshow', authenticateToken, async(req, res) => {
    try {
        console.log('API electionshow requested');

        // Fetch elections where registration is open (is_register = 1)
        const query = 'SELECT year, is_register, is_vote FROM election WHERE is_register = 1';
        const [rows] = await pool.execute(query);

        // Return the fetched data
        res.json(rows);

    } catch (error) {
        console.error('Error fetching elections with open registration:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint to fetch vote data based on year and roll_no
app.post('/api/votecheck', async(req, res) => {
    const { year, roll_no } = req.body;

    try {
        console.log("api votecheck requested")
            // Query to fetch election_id from election table based on year
        const electionQuery = `
            SELECT election_id
            FROM election
            WHERE year = ?
        `;

        // Execute the query to fetch election_id
        const [electionRows] = await pool.execute(electionQuery, [year]);

        if (electionRows.length === 0) {
            throw new Error('No election found for the given year');
        }

        const electionId = electionRows[0].election_id;

        // Query to fetch vote table data based on election_id and roll_no
        const voteQuery = `
            SELECT *
            FROM vote
            WHERE election_id = ? AND voter_roll_no = ?
        `;

        // Execute the query to fetch vote table data
        const [voteRows] = await pool.execute(voteQuery, [electionId, roll_no]);

        // Send the response with vote table data
        res.json(voteRows);

    } catch (error) {
        console.error('Error fetching vote data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Route for handling votes in the election
app.post('/api/vote', [authenticateToken, async(req, res) => {
    const { year, role_id, roll_no, candidate_id } = req.body;

    try {
        console.log(req.body)
        console.log("api vote requested")
            // Step 1: Get election_id from election table based on year
        const electionQuery = `
            SELECT election_id, is_vote
            FROM election
            WHERE year = ?
        `;
        const [electionResults] = await pool.execute(electionQuery, [year]);
        console.log(electionResults)
        if (electionResults.length === 0) {
            return res.status(404).json({ error: 'Election not found for the given year' });
        }

        const { election_id, is_vote } = electionResults[0];

        console.log(is_vote)
            // Step 2: Check if voting is closed
        if (is_vote !== 1) {
            return res.status(400).json({ error: 'Voting for this election is closed' });
        }

        // Step 4: Get candidate details
        const candidateQuery = `
              SELECT reg_roll_no, role_id, gender
              FROM candidate
              WHERE candidate_id = ?
          `;
        const [candidateResults] = await pool.execute(candidateQuery, [candidate_id]);
        console.log
        if (candidateResults.length === 0) {
            return res.status(404).json({ error: 'Candidate not found' });
        }

        const { reg_roll_no, candidate_role_id, gender } = candidateResults[0];


        // Log gender to console
        console.log('Candidate Gender:', gender);


        // Step 3: Check if the voter has already voted for this role and gender
        const voteCheckQuery = `
            SELECT COUNT(*) AS voteCount
            FROM vote
            WHERE role_id = ? AND gender = ? AND voter_roll_no = ?
        `;
        const [voteCheckResults] = await pool.execute(voteCheckQuery, [role_id, gender, roll_no]);

        if (voteCheckResults[0].voteCount > 0) {
            return res.status(400).json({ error: 'You have already voted for this role and gender' });
        }


        // Step 5: Insert the vote into the vote table
        const insertVoteQuery = `
            INSERT INTO vote (election_id, role_id, voter_roll_no, candidate_id, gender)
            VALUES (?, ?, ?, ?, ?)
        `;
        await pool.execute(insertVoteQuery, [election_id, role_id, roll_no, candidate_id, gender]);

        res.json({ success: true, message: 'Vote cast successfully' });

    } catch (error) {
        console.error('Error casting vote:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);





app.post('/api/voteresult', [authenticateToken, async(req, res) => {
    const { year } = req.body;

    try {
        console.log('API voteresult requested');
        if (!year) {
            return res.status(400).json({ error: 'Year is required in the request body' });
        }

        // Query to get election_id based on the provided year
        const electionIdQuery = 'SELECT election_id FROM election WHERE year = ?';
        const [electionIdResult] = await pool.execute(electionIdQuery, [year]);

        // Check if election exists for the provided year
        if (electionIdResult.length === 0) {
            return res.status(404).json({ error: 'No election found for the provided year' });
        }

        const { election_id } = electionIdResult[0];

        // Query to check if election is already published
        const checkPublishedQuery = 'SELECT is_vote, is_register FROM election WHERE election_id = ?';
        const [publishStatusResult] = await pool.execute(checkPublishedQuery, [election_id]);

        // Check if election is already published
        if (publishStatusResult.length > 0 && publishStatusResult[0].is_vote === 2 && publishStatusResult[0].is_register === 2) {
            return res.json({ message: 'Election result already published' });
        }


        // Query to get vote results for all role_ids and sorted by role_id
        const voteResultQuery = `
            SELECT v.role_id, v.candidate_id, c.reg_roll_no, c.gender, COUNT(*) as vote_count
            FROM vote v
            INNER JOIN candidate c ON v.candidate_id = c.candidate_id
            WHERE v.election_id = ?
            GROUP BY v.role_id, v.candidate_id, c.gender
            ORDER BY v.role_id, c.gender
        `;

        const [voteResults] = await pool.execute(voteResultQuery, [election_id]);

        if (voteResults.length === 0) {
            return res.status(404).json({ error: 'No vote results found for this election' });
        }

        // Query to fetch role information from roles table
        const rolesQuery = 'SELECT role_id, role_name FROM roles';
        const [roles] = await pool.execute(rolesQuery);

        // Map roles to role_id for quick lookup
        const roleMap = {};
        roles.forEach(role => {
            roleMap[role.role_id] = role.role_name;
        });

        // Query to fetch profiles and map roll_no to names
        const rollNos = voteResults.map(result => result.reg_roll_no);
        const profilesQuery = 'SELECT roll_no, name FROM profile WHERE roll_no IN (?)';
        const [profiles] = await pool.execute(profilesQuery, [rollNos]);

        // Map roll_no to names for quick lookup
        const nameMap = {};
        profiles.forEach(profile => {
            nameMap[profile.roll_no] = profile.name;
        });

        // Calculate total votes for each role_id and gender in the election
        const totalVotesQuery = `
            SELECT role_id, gender, COUNT(*) as total_votes
            FROM vote
            WHERE election_id = ?
            GROUP BY role_id, gender
        `;
        const [totalVotesResults] = await pool.execute(totalVotesQuery, [election_id]);

        // Map the total votes to a role_id and gender indexed object
        const totalVotesMap = {};
        totalVotesResults.forEach(result => {
            if (!totalVotesMap[result.role_id]) {
                totalVotesMap[result.role_id] = {};
            }
            totalVotesMap[result.role_id][result.gender] = result.total_votes;
        });

        // Format the results by role_id with vote results nested under each gender
        const formattedResults = [];

        // Group vote results by role_id and gender
        const groupedResults = {};
        voteResults.forEach(result => {
            if (!groupedResults[result.role_id]) {
                groupedResults[result.role_id] = {
                    role_id: result.role_id,
                    role_name: roleMap[result.role_id] || 'Unknown Role',
                    gender: {}
                };
            }
            if (!groupedResults[result.role_id].gender[result.gender]) {
                groupedResults[result.role_id].gender[result.gender] = {
                    total_votes: totalVotesMap[result.role_id][result.gender] || 0,
                    vote_results: []
                };
            }
            groupedResults[result.role_id].gender[result.gender].vote_results.push({
                candidate_id: result.candidate_id,
                reg_roll_no: result.reg_roll_no,
                gender: result.gender,
                vote_count: result.vote_count,
                vote_percentage: totalVotesMap[result.role_id][result.gender] > 0 ?
                    (result.vote_count / totalVotesMap[result.role_id][result.gender]) * 100 : 0,
                name: nameMap[result.reg_roll_no] || 'Unknown'
            });
        });

        // Push grouped results into formatted array
        Object.keys(groupedResults).forEach(role_id => {
            const roleData = groupedResults[role_id];
            const roleEntry = {
                role_id: roleData.role_id,
                role_name: roleData.role_name,
                gender: []
            };
            Object.keys(roleData.gender).forEach(gender => {
                const totalVotesGender = totalVotesMap[roleData.role_id][gender] || 0;
                roleEntry.gender.push({
                    [gender]: {
                        total_votes: totalVotesGender,
                        vote_results: roleData.gender[gender].vote_results.map(vote => ({
                            ...vote,
                            vote_percentage: totalVotesGender > 0 ?
                                (vote.vote_count / totalVotesGender) * 100 : 0
                        }))
                    }
                });
            });
            formattedResults.push(roleEntry);
        });

        // Update election table after processing
        const updateElectionQuery = 'UPDATE election SET is_vote = 2, is_register = 2 WHERE election_id = ?';
        await pool.execute(updateElectionQuery, [election_id]);

        // Return the formatted results sorted by role_id
        res.json({ success: true, results: formattedResults });
    } catch (error) {
        console.error('Error fetching vote results:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



app.post('/api/viewvoteresult', [authenticateToken, async(req, res) => {
    const { year } = req.body;

    try {
        console.log('API voteresult requested');
        if (!year) {
            return res.status(400).json({ error: 'Year is required in the request body' });
        }

        // Query to get election_id based on the provided year
        const electionIdQuery = 'SELECT election_id FROM election WHERE year = ?';
        const [electionIdResult] = await pool.execute(electionIdQuery, [year]);

        // Check if election exists for the provided year
        if (electionIdResult.length === 0) {
            return res.status(404).json({ error: 'No election found for the provided year' });
        }

        const { election_id } = electionIdResult[0];




        // Query to get vote results for all role_ids and sorted by role_id
        const voteResultQuery = `
            SELECT v.role_id, v.candidate_id, c.reg_roll_no, c.gender, COUNT(*) as vote_count
            FROM vote v
            INNER JOIN candidate c ON v.candidate_id = c.candidate_id
            WHERE v.election_id = ?
            GROUP BY v.role_id, v.candidate_id, c.gender
            ORDER BY v.role_id, c.gender
        `;

        const [voteResults] = await pool.execute(voteResultQuery, [election_id]);

        if (voteResults.length === 0) {
            return res.status(404).json({ error: 'No vote results found for this election' });
        }

        // Query to fetch role information from roles table
        const rolesQuery = 'SELECT role_id, role_name FROM roles';
        const [roles] = await pool.execute(rolesQuery);

        // Map roles to role_id for quick lookup
        const roleMap = {};
        roles.forEach(role => {
            roleMap[role.role_id] = role.role_name;
        });

        // Query to fetch profiles and map roll_no to names
        const rollNos = voteResults.map(result => result.reg_roll_no);
        const profilesQuery = 'SELECT roll_no, name FROM profile WHERE roll_no IN (?)';
        const [profiles] = await pool.execute(profilesQuery, [rollNos]);

        // Map roll_no to names for quick lookup
        const nameMap = {};
        profiles.forEach(profile => {
            nameMap[profile.roll_no] = profile.name;
        });

        // Calculate total votes for each role_id and gender in the election
        const totalVotesQuery = `
            SELECT role_id, gender, COUNT(*) as total_votes
            FROM vote
            WHERE election_id = ?
            GROUP BY role_id, gender
        `;
        const [totalVotesResults] = await pool.execute(totalVotesQuery, [election_id]);

        // Map the total votes to a role_id and gender indexed object
        const totalVotesMap = {};
        totalVotesResults.forEach(result => {
            if (!totalVotesMap[result.role_id]) {
                totalVotesMap[result.role_id] = {};
            }
            totalVotesMap[result.role_id][result.gender] = result.total_votes;
        });

        // Format the results by role_id with vote results nested under each gender
        const formattedResults = [];

        // Group vote results by role_id and gender
        const groupedResults = {};
        voteResults.forEach(result => {
            if (!groupedResults[result.role_id]) {
                groupedResults[result.role_id] = {
                    role_id: result.role_id,
                    role_name: roleMap[result.role_id] || 'Unknown Role',
                    gender: {}
                };
            }
            if (!groupedResults[result.role_id].gender[result.gender]) {
                groupedResults[result.role_id].gender[result.gender] = {
                    total_votes: totalVotesMap[result.role_id][result.gender] || 0,
                    vote_results: []
                };
            }
            groupedResults[result.role_id].gender[result.gender].vote_results.push({
                candidate_id: result.candidate_id,
                reg_roll_no: result.reg_roll_no,
                gender: result.gender,
                vote_count: result.vote_count,
                vote_percentage: totalVotesMap[result.role_id][result.gender] > 0 ?
                    (result.vote_count / totalVotesMap[result.role_id][result.gender]) * 100 : 0,
                name: nameMap[result.reg_roll_no] || 'Unknown'
            });
        });

        // Push grouped results into formatted array
        Object.keys(groupedResults).forEach(role_id => {
            const roleData = groupedResults[role_id];
            const roleEntry = {
                role_id: roleData.role_id,
                role_name: roleData.role_name,
                gender: []
            };
            Object.keys(roleData.gender).forEach(gender => {
                const totalVotesGender = totalVotesMap[roleData.role_id][gender] || 0;
                roleEntry.gender.push({
                    [gender]: {
                        total_votes: totalVotesGender,
                        vote_results: roleData.gender[gender].vote_results.map(vote => ({
                            ...vote,
                            vote_percentage: totalVotesGender > 0 ?
                                (vote.vote_count / totalVotesGender) * 100 : 0
                        }))
                    }
                });
            });
            formattedResults.push(roleEntry);
        });



        // Return the formatted results sorted by role_id
        res.json({ success: true, results: formattedResults });
    } catch (error) {
        console.error('Error fetching vote results:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

app.post('/api/winnerelectionresult', [authenticateToken, async(req, res) => {
    const { year } = req.body;

    try {
        console.log('API winnerelectionresult requested');
        if (!year) {
            return res.status(400).json({ error: 'Year is required in the request body' });
        }

        // Query to get election_id based on the provided year
        const electionIdQuery = 'SELECT election_id FROM election WHERE year = ?';
        const [electionIdResult] = await pool.execute(electionIdQuery, [year]);

        if (electionIdResult.length === 0) {
            return res.status(404).json({ error: 'No election found for the provided year' });
        }

        const { election_id } = electionIdResult[0];

        // Query to get vote results for all role_ids and sorted by role_id
        const voteResultQuery = `
            SELECT v.role_id, v.candidate_id, c.reg_roll_no, c.gender, COUNT(*) as vote_count
            FROM vote v
            INNER JOIN candidate c ON v.candidate_id = c.candidate_id
            WHERE v.election_id = ?
            GROUP BY v.role_id, v.candidate_id, c.gender
            ORDER BY v.role_id, c.gender
        `;

        const [voteResults] = await pool.execute(voteResultQuery, [election_id]);

        if (voteResults.length === 0) {
            return res.status(404).json({ error: 'No vote results found for this election' });
        }

        // Query to fetch roles information
        const rolesQuery = 'SELECT role_id, role_name FROM roles';
        const [roles] = await pool.execute(rolesQuery);

        const roleMap = {};
        roles.forEach(role => {
            roleMap[role.role_id] = role.role_name;
        });

        // Calculate total votes for each role_id and gender in the election
        const totalVotesQuery = `
            SELECT role_id, gender, COUNT(*) as total_votes
            FROM vote
            WHERE election_id = ?
            GROUP BY role_id, gender
        `;
        const [totalVotesResults] = await pool.execute(totalVotesQuery, [election_id]);

        const totalVotesMap = {};
        totalVotesResults.forEach(result => {
            if (!totalVotesMap[result.role_id]) {
                totalVotesMap[result.role_id] = {};
            }
            totalVotesMap[result.role_id][result.gender] = result.total_votes;
        });

        // Identify winners for each role and gender
        const winners = {};

        voteResults.forEach(result => {
            const { role_id, gender, vote_count, reg_roll_no } = result;
            const totalVotesGender = totalVotesMap[role_id][gender];
            const votePercentage = totalVotesGender > 0 ? (vote_count / totalVotesGender) * 100 : 0;

            if (!winners[role_id]) {
                winners[role_id] = {};
            }

            if (!winners[role_id][gender]) {
                winners[role_id][gender] = {
                    reg_roll_no: reg_roll_no,
                    vote_count: vote_count,
                    vote_percentage: votePercentage,
                    role_name: roleMap[role_id] || 'Unknown Role',
                    gender: gender
                };
            } else {
                if (vote_count > winners[role_id][gender].vote_count) {
                    winners[role_id][gender] = {
                        reg_roll_no: reg_roll_no,
                        vote_count: vote_count,
                        vote_percentage: votePercentage,
                        role_name: roleMap[role_id] || 'Unknown Role',
                        gender: gender
                    };
                }
            }
        });

        // Fetch profiles one by one
        const profileMap = {};
        const rollNos = Object.values(winners).flatMap(role => Object.values(role).map(winner => winner.reg_roll_no));
        console.log('Roll Nos to fetch profiles:', rollNos);

        if (rollNos.length === 0) {
            console.log('No roll numbers found to fetch profiles.');
        } else {
            for (const roll_no of rollNos) {
                console.log(`Fetching profile for roll_no: ${roll_no}`);
                const profileQuery = 'SELECT roll_no, name, photo_path FROM profile WHERE roll_no = ?';
                const [profile] = await pool.execute(profileQuery, [roll_no]);

                console.log(`Profile result for roll_no ${roll_no}:`, profile);

                if (profile.length > 0) {
                    const { name, photo_path } = profile[0];
                    profileMap[roll_no] = { name, photo_path };
                } else {
                    profileMap[roll_no] = { name: 'Unknown', photo_path: 'Unknown' };
                }
            }
        }

        console.log('Profile Map:', profileMap);

        // Assign names and photo_paths to winners
        Object.keys(winners).forEach(role_id => {
            Object.keys(winners[role_id]).forEach(gender => {
                const winner = winners[role_id][gender];
                const profile = profileMap[winner.reg_roll_no] || { name: 'Unknown', photo_path: 'Unknown' };
                winner.name = profile.name;
                winner.photo_path = profile.photo_path;
            });
        });

        console.log('Winners after name and photo path assignment:', winners);

        // Format the winners into the required structure
        const formattedWinners = Object.keys(winners).map(role_id => ({
            role_id: role_id,
            role_name: roleMap[role_id] || 'Unknown Role',
            gender: Object.keys(winners[role_id]).map(gender => ({
                gender: gender,
                ...winners[role_id][gender]
            }))
        }));

        console.log('Formatted winners:', formattedWinners);

        res.json({ success: true, winners: formattedWinners });

    } catch (error) {
        console.error('Error fetching winner results:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




// Route for updating SPL roles in the login table
app.post('/api/updatingsplroles', [authenticateToken, async(req, res) => {
    const { roll_no, role_id } = req.body;

    try {
        console.log('API updatingsroles requested');
        if (!roll_no || !role_id) {
            return res.status(400).json({ error: 'Roll number and role ID are required in the request body' });
        }

        // Query to update SPL role in the login table
        const updateQuery = `
            UPDATE login
            SET spl_role = ?
            WHERE roll_no = ?
        `;

        const [result] = await pool.execute(updateQuery, [role_id, roll_no]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User with the provided roll number not found' });
        }

        res.json({ success: true, message: 'SPL role updated successfully' });
    } catch (error) {
        console.error('Error updating SPL role:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




// Function to delete non-`.txt` files from a given directory
const deleteNonTxtFiles = (directoryPath) => {
    return new Promise((resolve, reject) => {
        fs.readdir(directoryPath, (err, files) => {
            if (err) {
                return reject(`Error reading directory ${directoryPath}: ${err.message}`);
            }

            // Filter out files that do not end with .txt
            const nonTxtFiles = files.filter(file => path.extname(file).toLowerCase() !== '.txt');

            if (nonTxtFiles.length === 0) {
                console.log(`No non-txt files found in ${directoryPath}`);
                return resolve(`No non-txt files found in ${directoryPath}`);
            }

            // Delete non-txt files
            let deletionPromises = nonTxtFiles.map(file => {
                return new Promise((fileResolve, fileReject) => {
                    const filePath = path.join(directoryPath, file);
                    fs.unlink(filePath, err => {
                        if (err) {
                            console.error(`Error deleting file ${file} in ${directoryPath}:`, err);
                            fileReject(`Error deleting file ${file} in ${directoryPath}`);
                        } else {
                            console.log(`Deleted file: ${file} in ${directoryPath}`);
                            fileResolve();
                        }
                    });
                });
            });

            // Wait for all deletions to complete
            Promise.all(deletionPromises)
                .then(() => resolve(`Non-txt files deleted successfully in ${directoryPath}`))
                .catch(error => reject(error));
        });
    });
};




// intra macthes

// API route for creating a new intramatch with gender
app.post('/api/intramatches', [authenticateToken, async(req, res) => {
    const { sport_id, house1, house2, house3, house4, date_time, year, gender } = req.body;

    try {
        console.log('API intramatches requested');

        // Validate required fields
        if (!sport_id || !house1 || !house2 || !house3 || !house4 || !date_time || !year || !gender) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if a match with the same gender, sport_id, and year already exists
        const checkQuery = `
            SELECT m_id 
            FROM matches 
            WHERE sport_id = ? AND year = ? AND gender = ?
        `;
        const [existingMatches] = await pool.execute(checkQuery, [sport_id, year, gender]);

        if (existingMatches.length > 0) {
            return res.status(400).json({ error: 'A match in a year with same gender already exists' });
        }

        // Insert new match into the matches table with gender
        const insertQuery = `
            INSERT INTO matches (sport_id, house1, house2, house3, house4, date_time, year, gender) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const [insertResult] = await pool.execute(insertQuery, [sport_id, house1, house2, house3, house4, date_time, year, gender]);

        // Retrieve the auto-generated match_id from the insert result
        const match_id = insertResult.insertId;

        res.json({ success: true, match_id, message: 'New match inserted successfully' });
    } catch (error) {
        console.error('Error creating intramatch:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// API route for displaying intramatches by year
app.post('/api/displayintramatches', async(req, res) => {
    const { year } = req.body;

    try {
        console.log('API displayintramatches requested');

        // Validate that the year is provided
        if (!year) {
            return res.status(400).json({ error: 'Year is required' });
        }

        // Query to select matches and join with sports table
        const query = `
            SELECT 
                m.match_id,
                m.sport_id,
                s.sport_name,
                m.house1,
                m.house2,
                m.house3,
                m.house4,
                m.date_time,
                m.year
            FROM 
                matches m
            JOIN 
                sports s ON m.sport_id = s.sport_id
            WHERE 
                m.year = ?
        `;

        const [results] = await pool.execute(query, [year]);

        // Check if matches were found
        if (results.length === 0) {
            return res.status(404).json({ message: 'No matches found for the specified year' });
        }

        res.json({ success: true, matches: results });
    } catch (error) {
        console.error('Error displaying intramatches:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API route for inserting intrapoints with gender, sports_id, and year
app.post('/api/intrapoints', [authenticateToken, async(req, res) => {
    const { gender, sports_id, year, amritamayi, anandmayi, chinmayi, jyotirmayi } = req.body;

    try {
        console.log('API intrapoints requested');

        // Validate required fields
        if (!gender || !sports_id || !year || amritamayi === undefined || anandmayi === undefined || chinmayi === undefined || jyotirmayi === undefined) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Find the m_id from the matches table
        const findMatchQuery = `
            SELECT match_id 
            FROM matches 
            WHERE gender = ? AND sport_id = ? AND year = ?
        `;
        const [matchRows] = await pool.execute(findMatchQuery, [gender, sports_id, year]);

        if (matchRows.length === 0) {
            return res.status(404).json({ error: 'No matching match found' });
        }

        // Retrieve the m_id (assuming the match_id is what you need)
        const m_id = matchRows[0].match_id;

        // Insert new points into the points table
        const insertQuery = `
            INSERT INTO points (m_id, amritamayi, anandmayi, chinmayi, jyotirmayi)
            VALUES (?, ?, ?, ?, ?)
        `;
        const [insertResult] = await pool.execute(insertQuery, [m_id, amritamayi, anandmayi, chinmayi, jyotirmayi]);

        // Retrieve the auto-generated points_id from the insert result
        const points_id = insertResult.insertId;

        res.json({ success: true, points_id, message: 'Points data inserted successfully' });
    } catch (error) {
        console.error('Error inserting intrapoints:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);
























// DELETE endpoint to remove non-.txt files from both 'uploads' and 'pdf' directories
app.delete('/api/delete-non-txt', async(req, res) => {
    try {
        const uploadsFolder = path.join(__dirname, 'uploads');
        const pdfFolder = path.join(__dirname, 'pdf');

        // Delete non-txt files from both directories
        let messages = [];

        const uploadsResult = await deleteNonTxtFiles(uploadsFolder);
        messages.push(uploadsResult);

        const pdfResult = await deleteNonTxtFiles(pdfFolder);
        messages.push(pdfResult);

        // Respond with the success messages
        res.json({ message: messages.join(', ') });
    } catch (error) {
        console.error('Error during file deletion:', error);
        res.status(500).json({ error: 'Internal Server Error' });
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


app.get('/test', (req, res) => {
    res.status(200).json({ message: "Welcome Aagneya" });
});



//port
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});